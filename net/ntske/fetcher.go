package ntske

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"

	"go.uber.org/zap"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/daemon"

	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

type Fetcher struct {
	Log       *zap.Logger
	TLSConfig tls.Config
	Port      string
	SCIONQuic struct {
		Enabled    bool
		RemoteAddr udp.UDPAddr
		LocalAddr  udp.UDPAddr
		DaemonAddr string
	}
	data Data
}

func (f *Fetcher) exchangeKeys() error {
	if f.SCIONQuic.Enabled {
		ctx := context.Background()

		dc := newDaemonConnector(f.Log, ctx, f.SCIONQuic.DaemonAddr)
		ps, err := dc.Paths(ctx, f.SCIONQuic.RemoteAddr.IA, f.SCIONQuic.LocalAddr.IA, daemon.PathReqFlags{Refresh: true})
		if err != nil {
			f.Log.Fatal("failed to lookup paths", zap.Stringer("to", f.SCIONQuic.RemoteAddr.IA), zap.Error(err))
		}
		if len(ps) == 0 {
			f.Log.Fatal("no paths available", zap.Stringer("to", f.SCIONQuic.RemoteAddr.IA))
		}
		f.Log.Debug("available paths", zap.Stringer("to", f.SCIONQuic.RemoteAddr.IA), zap.Array("via", scion.PathArrayMarshaler{Paths: ps}))
		sp := ps[0]
		f.Log.Debug("selected path", zap.Stringer("to", f.SCIONQuic.RemoteAddr.IA), zap.Object("via", scion.PathMarshaler{Path: sp}))

		conn, err := scion.DialQUIC(ctx, f.SCIONQuic.LocalAddr, f.SCIONQuic.RemoteAddr, sp,
			"" /* host*/, &f.TLSConfig, nil /* quicCfg */)
		if err != nil {
			return err
		}
		defer func() {
			err := conn.CloseWithError(quic.ApplicationErrorCode(0), "" /* error string */)
			if err != nil {
				log.Fatal("failed to close connection", zap.Error(err))
			}
		}()

		for i := 0; i < 3; i++ {
			stream, err := conn.OpenStream()
			if err != nil {
				return err
			}
			defer quic.SendStream(stream).Close()

			kes := new(KeyExchangeSCION)

			var msg ExchangeMsg
			var nextproto NextProto

			nextproto.NextProto = NTPv4
			msg.AddRecord(nextproto)

			var algo Algorithm
			algo.Algo = []uint16{AES_SIV_CMAC_256}
			msg.AddRecord(algo)

			var end End
			msg.AddRecord(end)

			buf, err := msg.Pack()
			if err != nil {
				return err
			}

			_, err = stream.Write(buf.Bytes())
			if err != nil {
				return err
			}
			quic.SendStream(stream).Close()
			kes.reader = bufio.NewReader(stream)

			// Wait for response
			err = kes.Read()
			if err != nil {
				return err
			}
			kes.Conn = conn.Connection
			kes.ExportKeys()

			logData(f.Log, kes.Meta)
			f.data = kes.Meta

			return nil
		}
	}

	serverAddr := net.JoinHostPort(f.TLSConfig.ServerName, f.Port)
	ke, err := Connect(serverAddr, &f.TLSConfig, false /* debug */)
	if err != nil {
		return err
	}

	err = ke.Exchange()
	if err != nil {
		return err
	}

	if len(ke.Meta.Cookie) == 0 {
		return errors.New("unexpected NTS-KE meta data: no cookies")
	}
	if ke.Meta.Algo != AES_SIV_CMAC_256 {
		return errors.New("unexpected NTS-KE meta data: unknown algorithm")
	}

	err = ke.ExportKeys()
	if err != nil {
		return err
	}

	logData(f.Log, ke.Meta)
	f.data = ke.Meta
	return nil
}

func (f *Fetcher) FetchData() (Data, error) {
	if len(f.data.Cookie) == 0 {
		err := f.exchangeKeys()
		if err != nil {
			return Data{}, err
		}
	}
	data := f.data
	f.data.Cookie = f.data.Cookie[1:]
	return data, nil
}

func (f *Fetcher) StoreCookie(cookie []byte) {
	f.data.Cookie = append(f.data.Cookie, cookie)
}
