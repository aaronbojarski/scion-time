package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"

	"github.com/secure-io/siv-go"

	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
)

const (
	cookieTypeAlgorithm uint16 = 0x101
	cookieTypeKeyS2C    uint16 = 0x201
	cookieTypeKeyC2S    uint16 = 0x301

	cookieTypeKeyID      uint16 = 0x401
	cookieTypeNonce      uint16 = 0x501
	cookieTypeCiphertext uint16 = 0x601
)

const (
	cookiesecret string = "12345678901234567890123456789012"
	cookiekeyid  int    = 17
)

type PlainCookie struct {
	Algo uint16
	S2C  []byte
	C2S  []byte
}

// Encodes cookie to byte slice with following format for each field
// uint16 | uint16 | []byte
// type   | length | value
func (c *PlainCookie) Encode() (b []byte, err error) {
	var cookiesize int = 3*4 + 2 + len(c.C2S) + len(c.S2C)
	b = make([]byte, cookiesize)
	binary.BigEndian.PutUint16((b)[0:], cookieTypeAlgorithm)
	binary.BigEndian.PutUint16((b)[2:], 0x2)
	binary.BigEndian.PutUint16((b)[4:], c.Algo)
	binary.BigEndian.PutUint16((b)[6:], cookieTypeKeyS2C)
	binary.BigEndian.PutUint16((b)[8:], uint16(len(c.S2C)))
	copy((b)[10:], c.S2C)
	pos := len(c.S2C) + 10
	binary.BigEndian.PutUint16((b)[pos:], cookieTypeKeyC2S)
	binary.BigEndian.PutUint16((b)[pos+2:], uint16(len(c.C2S)))
	copy((b)[pos+4:], c.C2S)
	return b, nil
}

func (c *PlainCookie) Decode(b []byte) {
	var pos int = 0
	for pos < len(b) {
		var t uint16 = binary.BigEndian.Uint16(b[pos:])
		var len uint16 = binary.BigEndian.Uint16(b[pos+2:])
		if t == cookieTypeAlgorithm {
			c.Algo = binary.BigEndian.Uint16(b[pos+4:])
		} else if t == cookieTypeKeyS2C {
			c.S2C = b[pos+4 : pos+4+int(len)]
		} else if t == cookieTypeKeyC2S {
			c.C2S = b[pos+4 : pos+4+int(len)]
		}
		pos += 4 + int(len)
	}
}

type EncryptedCookie struct {
	ID         uint16
	Nonce      []byte
	Ciphertext []byte
}

func (c *EncryptedCookie) Encode() (b []byte, err error) {
	var encryptedcookiesize int = 3*4 + 2 + len(c.Nonce) + len(c.Ciphertext)
	b = make([]byte, encryptedcookiesize)
	binary.BigEndian.PutUint16((b)[0:], cookieTypeKeyID)
	binary.BigEndian.PutUint16((b)[2:], 0x2)
	binary.BigEndian.PutUint16((b)[4:], c.ID)
	binary.BigEndian.PutUint16((b)[6:], cookieTypeNonce)
	binary.BigEndian.PutUint16((b)[8:], uint16(len(c.Nonce)))
	copy((b)[10:], c.Nonce)
	pos := len(c.Nonce) + 10
	binary.BigEndian.PutUint16((b)[pos:], cookieTypeCiphertext)
	binary.BigEndian.PutUint16((b)[pos+2:], uint16(len(c.Ciphertext)))
	copy((b)[pos+4:], c.Ciphertext)
	return b, nil
}

func (c *EncryptedCookie) Decode(b []byte) {
	var pos int = 0
	for pos < len(b) {
		var t uint16 = binary.BigEndian.Uint16(b[pos:])
		var len uint16 = binary.BigEndian.Uint16(b[pos+2:])
		if t == cookieTypeKeyID {
			c.ID = binary.BigEndian.Uint16(b[pos+4:])
		} else if t == cookieTypeNonce {
			c.Nonce = b[pos+4 : pos+4+int(len)]
		} else if t == cookieTypeCiphertext {
			c.Ciphertext = b[pos+4 : pos+4+int(len)]
		}
		pos += 4 + int(len)
	}
}

func (c *PlainCookie) Encrypt(key []byte, keyid int) (EncryptedCookie, error) {
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

	b, err := c.Encode()
	if err != nil {
		return ecookie, err
	}

	ecookie.Ciphertext = aessiv.Seal(nil, ecookie.Nonce, b, nil)

	return ecookie, nil
}

func (c *EncryptedCookie) Decrypt(key []byte, keyid int) (PlainCookie, error) {
	var cookie PlainCookie

	if c.ID != uint16(keyid) {
		return cookie, errors.New("Wrong Key ID")
	}

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		return cookie, err
	}

	b, err := aessiv.Open(nil, c.Nonce, c.Ciphertext, nil)
	if err != nil {
		return cookie, err
	}
	cookie.Decode(b)
	if err != nil {
		return cookie, err
	}
	return cookie, nil
}

func runNTSKEServer(log *zap.Logger, listener net.Listener) {
	log.Info("server NTSKE listening via IP")

	for {
		ke, err := ntske.NewListener(listener)
		if err != nil {
			log.Error("server: accept", zap.Error(err))
			break
		}

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

		var nextproto ntske.NextProto
		nextproto.NextProto = ntske.NTPv4
		msg.AddRecord(nextproto)

		var algo ntske.Algorithm
		algo.Algo = []uint16{ntske.AES_SIV_CMAC_256}
		msg.AddRecord(algo)

		var server ntske.Server
		server.Addr = []byte("127.0.0.1")
		msg.AddRecord(server)

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
				continue
			}

			b, err := ecookie.Encode()
			if err != nil {
				log.Error("Couldn't encode cookie", zap.Error(err))
				continue
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
			log.Error("failed sending response", zap.Error(err))
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
