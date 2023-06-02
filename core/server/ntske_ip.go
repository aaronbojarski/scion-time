package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strconv"

	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
)

func sendMessageWithError(log *zap.Logger, conn *tls.Conn, code int) {
	var msg ntske.ExchangeMsg
	msg.AddRecord(ntske.Error{
		Code: uint16(code),
	})

	buf, err := msg.Pack()
	if err != nil {
		log.Info("failed to build packet", zap.Error(err))
		return
	}

	n, err := conn.Write(buf.Bytes())
	if err != nil || n != buf.Len() {
		log.Info("failed to write response", zap.Error(err))
		return
	}
}

func handleKeyExchange(log *zap.Logger, conn *tls.Conn, localPort int, provider *ntske.Provider) {
	defer conn.Close()

	var err error
	var data ntske.Data
	reader := bufio.NewReader(conn)
	err = ntske.Read(log, reader, &data)
	if err != nil {
		log.Info("failed to read key exchange", zap.Error(err))
		sendMessageWithError(log, conn, 1)
		return
	}

	err = ntske.ExportKeys(conn.ConnectionState(), &data)
	if err != nil {
		log.Info("failed to export keys", zap.Error(err))
		sendMessageWithError(log, conn, 2)
		return
	}

	localIP := conn.LocalAddr().(*net.TCPAddr).IP

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
	plaintextCookie.C2S = data.C2sKey
	plaintextCookie.S2C = data.S2cKey
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
		log.Info("failed to add at least one cookie")
		sendMessageWithError(log, conn, 2)
		return
	}

	msg.AddRecord(ntske.End{})

	buf, err := msg.Pack()
	if err != nil {
		log.Info("failed to build packet", zap.Error(err))
		sendMessageWithError(log, conn, 2)
		return
	}

	n, err := conn.Write(buf.Bytes())
	if err != nil || n != buf.Len() {
		log.Info("failed to write response", zap.Error(err))
		return
	}
}

func runNTSKEServer(log *zap.Logger, listener net.Listener, localPort int, provider *ntske.Provider) {
	for {
		conn, err := ntske.NewTCPListener(listener)
		if err != nil {
			log.Info("failed to accept client", zap.Error(err))
			continue
		}
		go handleKeyExchange(log, conn, localPort, provider)
	}
}

func StartNTSKEServer(ctx context.Context, log *zap.Logger, localIP net.IP, localPort int, config *tls.Config, provider *ntske.Provider) {
	ntskeAddr := net.JoinHostPort(localIP.String(), strconv.Itoa(defaultNtskePort))
	log.Info("server listening via IP",
		zap.Stringer("ip", localIP),
		zap.Int("port", defaultNtskePort),
	)

	listener, err := tls.Listen("tcp", ntskeAddr, config)
	if err != nil {
		log.Error("failed to create TLS listener")
	}

	go runNTSKEServer(log, listener, localPort, provider)
}
