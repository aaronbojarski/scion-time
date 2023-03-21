package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"net"
	"os"

	"github.com/secure-io/siv-go"

	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
)

type PlainCookie struct {
	Algo uint16
	S2C  []byte
	C2S  []byte
}

func pack(v interface{}) (buf *bytes.Buffer, err error) {
	buf = new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(v)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func (c PlainCookie) Encrypt(key []byte, keyid int) (EncryptedCookie, error) {
	var ecookie EncryptedCookie

	ecookie.ID = uint16(keyid)
	bits := make([]byte, 16)
	_, err := rand.Read(bits)
	if err != nil {
		return ecookie, err
	}
	ecookie.Nonce = bits

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		return ecookie, err
	}

	buf, err := c.Pack()
	if err != nil {
		return ecookie, err
	}

	ecookie.Ciphertext = aessiv.Seal(nil, ecookie.Nonce, buf.Bytes(), nil)

	return ecookie, nil
}

func (c PlainCookie) Pack() (buf *bytes.Buffer, err error) {
	// suggested format
	// uint16 | uint16 | []byte
	// type   | length | value
	// var cookiesize int = 3*4 + 2 + len(c.C2S) + len(c.S2C)
	// b := make([]byte, cookiesize)
	
	return pack(c)
}

type EncryptedCookie struct {
	ID         uint16
	Nonce      []byte
	Ciphertext []byte
}

func (c EncryptedCookie) Pack() (buf *bytes.Buffer, err error) {
	return pack(c)
}

func runNTSKEServer(log *zap.Logger, listener net.Listener) {

	var cookiesecret string = "12345678901234567890123456789012"
	var cookiekeyid int = 17
	log.Info("server NTSKE listening via IP")

	for {
		ke, err := ntske.NewListener(listener)
		if err != nil {
			log.Error("server: accept: %s", zap.Error(err))
			break
		}
		log.Info("Handling request")

		err = ke.Read()
		if err != nil {
			log.Error("Read Key Exchange", zap.Error(err))
			return
		}

		err = ke.ExportKeys()
		if err != nil {
			log.Error("Key Exchange export", zap.Error(err))
			return
		}

		var msg ntske.ExchangeMsg

		// We're speaking NTPv4 next
		var nextproto ntske.NextProto
		nextproto.NextProto = ntske.NTPv4
		msg.AddRecord(nextproto)

		// Using AES SIV for NTS
		var algo ntske.Algorithm
		algo.Algo = []uint16{ntske.AES_SIV_CMAC_256}
		msg.AddRecord(algo)

		// You're supposed to ask this server for time
		var server ntske.Server
		server.Addr = []byte("127.0.0.1")
		msg.AddRecord(server)

		// On this port
		var port ntske.Port
		port.Port = 1234
		msg.AddRecord(port)

		for i := 0; i < 8; i++ {
			var plaincookie PlainCookie
			plaincookie.Algo = ntske.AES_SIV_CMAC_256
			plaincookie.C2S = ke.Meta.C2sKey
			plaincookie.S2C = ke.Meta.S2cKey

			ecookie, err := plaincookie.Encrypt([]byte(cookiesecret), cookiekeyid)
			if err != nil {
				log.Error("Couldn't encrypt cookie", zap.Error(err))
				os.Exit(1)
			}

			buf, err := ecookie.Pack()
			if err != nil {
				os.Exit(1)
			}

			var cookie ntske.Cookie
			cookie.Cookie = buf.Bytes()

			msg.AddRecord(cookie)
		}

		var end ntske.End
		msg.AddRecord(end)

		buf, err := msg.Pack()
		if err != nil {
			return
		}

		_, err = ke.Conn.Write(buf.Bytes())

		if err != nil {
			log.Error("Send response", zap.Error(err))
		}
	}
}

func StartNTSKEServer(ctx context.Context, log *zap.Logger,
	localHost *net.UDPAddr) {
	certs, err := tls.LoadX509KeyPair("./core/server/tls.crt", "./core/server/tls.key")
	if err != nil {
		log.Error("TLS Key load", zap.Error(err))
		return
	}

	config := &tls.Config{
		ServerName:   "localhost",
		NextProtos:   []string{"ntske/1"},
		Certificates: []tls.Certificate{certs},
		MinVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:4600", config)
	go runNTSKEServer(log, listener)
}
