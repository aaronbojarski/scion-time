package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

func handleSCIONKeyExchange(log *zap.Logger, conn quic.Connection, localPort int, provider *ntske.Provider) error {

	i := 0
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		defer quic.SendStream(stream).Close()

		ke := ntske.NewSCIONListener(context.Background(), conn, bufio.NewReader(stream))

		err = ke.Read()
		if err != nil {
			return errors.New("failed to read key exchange")
		}

		err = ke.ExportKeys()
		if err != nil {
			return errors.New("failed to export keys")
		}

		localIP := ke.Conn.LocalAddr().(udp.UDPAddr).Host.IP

		var msg ntske.ExchangeMsg
		msg.AddRecord(ntske.NextProto{
			NextProto: ntske.NTPv4,
		})
		msg.AddRecord(ntske.Algorithm{
			Algo: []uint16{ntske.AES_SIV_CMAC_256},
		})
		msg.AddRecord(ntske.Server{
			Addr: []byte(localIP.String()),
		})
		msg.AddRecord(ntske.Port{
			Port: uint16(localPort),
		})

		var plaintextCookie ntske.ServerCookie
		plaintextCookie.Algo = ntske.AES_SIV_CMAC_256
		plaintextCookie.C2S = ke.Meta.C2sKey
		plaintextCookie.S2C = ke.Meta.S2cKey
		key := provider.Current()
		addedCookie := false
		for i := 0; i < 8; i++ {
			encryptedCookie, err := plaintextCookie.EncryptWithNonce(key.Value, key.ID)
			if err != nil {
				log.Info("failed to encrypt cookie", zap.Error(err))
				continue
			}

			b := encryptedCookie.Encode()
			msg.AddRecord(ntske.Cookie{
				Cookie: b,
			})
			addedCookie = true
		}
		if !addedCookie {
			return errors.New("failed to add at least one cookie")
		}

		msg.AddRecord(ntske.End{})

		buf, err := msg.Pack()
		if err != nil {
			return errors.New("failed to build packet")
		}

		_, err = stream.Write(buf.Bytes())
		if err != nil {
			return err
		}

		quic.SendStream(stream).Close()
		i++

		log.Info("STREAM WRITTEN")
		return nil
	}
}

func runSCIONNTSKEServer(ctx context.Context, log *zap.Logger, listener quic.Listener, localPort int, provider *ntske.Provider) {
	defer listener.Close()
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			log.Info("failed to accept connection", zap.Error(err))
			continue
		}
		log.Info("accepted connection", zap.Stringer("remote", conn.RemoteAddr()))
		go func() {
			err := handleSCIONKeyExchange(log, conn, localPort, provider)
			var errApplication *quic.ApplicationError
			if err != nil && !(errors.As(err, &errApplication) && errApplication.ErrorCode == 0) {
				log.Info("failed to handle connection",
					zap.Stringer("remote", conn.RemoteAddr()),
					zap.Error(err),
				)
			}
		}()
	}
}

func StartSCIONNTSKEServer(ctx context.Context, log *zap.Logger, localIP net.IP, localPort int, config *tls.Config, provider *ntske.Provider, localAddr udp.UDPAddr) {
	//ntskeAddr := net.JoinHostPort(localIP.String(), strconv.Itoa(defaultNtskePort))
	log.Info("server listening via SCION",
		zap.Stringer("ip", localIP),
		zap.Int("port", defaultNtskePort),
	)

	localAddr.Host.Port = defaultNtskePort

	listener, err := scion.ListenQUIC(ctx, localAddr, config, nil /* quicCfg */)
	if err != nil {
		log.Fatal("failed to start listening", zap.Error(err))
	}

	go runSCIONNTSKEServer(ctx, log, listener, localPort, provider)

}
