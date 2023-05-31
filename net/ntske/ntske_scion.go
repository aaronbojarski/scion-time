package ntske

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/daemon"
)

// KeyExchange is Network Time Security Key Exchange connection
type KeyExchangeSCION struct {
	hostport string
	Conn     quic.Connection
	reader   *bufio.Reader
	Meta     Data
	Debug    bool
}

func newDaemonConnector(log *zap.Logger, ctx context.Context, daemonAddr string) daemon.Connector {
	if daemonAddr == "" {
		return nil
	}
	s := &daemon.Service{
		Address: daemonAddr,
	}
	c, err := s.Connect(ctx)
	if err != nil {
		log.Fatal("failed to create demon connector", zap.Error(err))
	}
	return c
}

func NewSCIONListener(ctx context.Context, conn quic.Connection, reader *bufio.Reader) *KeyExchangeSCION {
	ke := new(KeyExchangeSCION)
	ke.Conn = conn
	ke.reader = reader
	return ke
}

// ExportKeys exports two extra sessions keys from the already
// established NTS-KE connection for use with NTS.
func (ke *KeyExchangeSCION) ExportKeys() error {
	label := "EXPORTER-network-time-security"
	s2cContext := []byte{0x00, 0x00, 0x00, 0x0f, 0x01}
	c2sContext := []byte{0x00, 0x00, 0x00, 0x0f, 0x00}
	len := 32

	var err error
	cs := ke.Conn.ConnectionState().TLS.ConnectionState
	ke.Meta.S2cKey, err = cs.ExportKeyingMaterial(label, s2cContext, len)
	if err != nil {
		return err
	}

	ke.Meta.C2sKey, err = cs.ExportKeyingMaterial(label, c2sContext, len)
	if err != nil {
		return err
	}

	return nil
}

// Read reads incoming NTS-KE messages until an End of Message record
// is received or an error occur. It fills out the ke.Meta structure
// with negotiated data.
func (ke *KeyExchangeSCION) Read() error {
	var msg RecordHdr
	var critical bool

	for {
		err := binary.Read(ke.reader, binary.BigEndian, &msg)
		if err != nil {
			return err
		}

		if hasBit(msg.Type, 15) {
			critical = true
		} else {
			critical = false
		}

		// Get rid of Critical bit.
		msg.Type &^= (1 << 15)

		if ke.Debug {
			fmt.Printf("Record type %v\n", msg.Type)
			if critical {
				fmt.Printf("Critical set\n")
			}
		}

		switch msg.Type {
		case RecEom:
			// Check that we have complete data.
			// if len(ke.Meta.Cookie) == 0 || ke.Meta.Algo == 0 {
			// 	return errors.New("incomplete data")
			// }

			return nil

		case RecNextproto:
			var nextProto uint16
			err := binary.Read(ke.reader, binary.BigEndian, &nextProto)
			if err != nil {
				return errors.New("buffer overrun")
			}

		case RecAead:
			var aead uint16
			err := binary.Read(ke.reader, binary.BigEndian, &aead)
			if err != nil {
				return errors.New("buffer overrun")
			}

			ke.Meta.Algo = aead

		case RecCookie:
			cookie := make([]byte, msg.BodyLen)
			_, err := ke.reader.Read(cookie)
			if err != nil {
				return errors.New("buffer overrun")
			}

			ke.Meta.Cookie = append(ke.Meta.Cookie, cookie)

		case RecServer:
			address := make([]byte, msg.BodyLen)

			err := binary.Read(ke.reader, binary.BigEndian, &address)
			if err != nil {
				return errors.New("buffer overrun")
			}
			ke.Meta.Server = string(address)
			if ke.Debug {
				fmt.Printf("(got negotiated NTP server: %v)\n", ke.Meta.Server)
			}

		case RecPort:
			err := binary.Read(ke.reader, binary.BigEndian, &ke.Meta.Port)
			if err != nil {
				return errors.New("buffer overrun")
			}
			if ke.Debug {
				fmt.Printf("(got negotiated NTP port: %v)\n", ke.Meta.Port)
			}

		default:
			if critical {
				return fmt.Errorf("unknown record type %v with critical bit set", msg.Type)
			}

			// Swallow unknown record.
			unknownMsg := make([]byte, msg.BodyLen)
			err := binary.Read(ke.reader, binary.BigEndian, &unknownMsg)
			if err != nil {
				return errors.New("buffer overrun")
			}
		}
	}
}
