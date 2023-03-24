package ntske

import (
	"encoding/hex"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type CookieArrayMarshaler struct {
	Cookies [][]byte
}

func (m CookieArrayMarshaler) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, c := range m.Cookies {
		enc.AppendString(hex.EncodeToString(c))
	}
	return nil
}

func logData(log *zap.Logger, data Data) {
	log.Debug("NTSKE data",
		zap.String("c2s", hex.EncodeToString(data.C2sKey)),
		zap.String("s2c", hex.EncodeToString(data.S2cKey)),
		zap.String("server", data.Server),
		zap.Uint16("port", data.Port),
		zap.Uint16("algo", data.Algo),
		zap.Array("cookies", CookieArrayMarshaler{Cookies: data.Cookie}))
}
