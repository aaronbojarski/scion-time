package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
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

	b, err := c.Pack()
	if err != nil {
		return ecookie, err
	}

	ecookie.Ciphertext = aessiv.Seal(nil, ecookie.Nonce, b, nil)

	return ecookie, nil
}

func (c PlainCookie) Pack() (b []byte, err error) {
	// suggested format
	// uint16 | uint16 | []byte
	// type   | length | value
	var cookiesize int = 3*4 + 2 + len(c.C2S) + len(c.S2C)
	b = make([]byte, cookiesize)
	binary.BigEndian.PutUint16((b)[0:], 0x101)
	binary.BigEndian.PutUint16((b)[2:], 0x2)
	binary.BigEndian.PutUint16((b)[4:], c.Algo)
	binary.BigEndian.PutUint16((b)[6:], 0x201)
	binary.BigEndian.PutUint16((b)[8:], uint16(len(c.S2C)))
	copy((b)[10:], c.S2C)
	pos := len(c.S2C) + 10
	binary.BigEndian.PutUint16((b)[pos:], 0x301)
	binary.BigEndian.PutUint16((b)[pos+2:], uint16(len(c.C2S)))
	copy((b)[pos+4:], c.C2S)
	return b, nil
}

type EncryptedCookie struct {
	ID         uint16
	Nonce      []byte
	Ciphertext []byte
}

func (c EncryptedCookie) Pack() (b []byte, err error) {
	var encryptedcookiesize int = 3*4 + 2 + len(c.Nonce) + len(c.Ciphertext)
	b = make([]byte, encryptedcookiesize)
	binary.BigEndian.PutUint16((b)[0:], 0x401)
	binary.BigEndian.PutUint16((b)[2:], 0x2)
	binary.BigEndian.PutUint16((b)[4:], c.ID)
	binary.BigEndian.PutUint16((b)[6:], 0x501)
	binary.BigEndian.PutUint16((b)[8:], uint16(len(c.Nonce)))
	copy((b)[10:], c.Nonce)
	pos := len(c.Nonce) + 10
	binary.BigEndian.PutUint16((b)[pos:], 0x601)
	binary.BigEndian.PutUint16((b)[pos+2:], uint16(len(c.Ciphertext)))
	copy((b)[pos+4:], c.Ciphertext)
	return b, nil
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

			b, err := ecookie.Pack()
			if err != nil {
				os.Exit(1)
			}

			var cookie ntske.Cookie
			cookie.Cookie = b

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
