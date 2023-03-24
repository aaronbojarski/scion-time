package ntske

import (
	"crypto/tls"
	"errors"

	"go.uber.org/zap"
)

type Fetcher struct {
	TLSConfig tls.Config
	Log       *zap.Logger
	data      Data
}

func (f *Fetcher) exchangeKeys() error {
	ke, err := Connect(f.TLSConfig.ServerName, &f.TLSConfig, false)
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

func (f *Fetcher) FetchData() (data Data, err error) {
	if len(data.Cookie) == 0 {
		err = f.exchangeKeys()
		if err != nil {
			return data, err
		}
	}
	data = f.data
	f.data.Cookie = f.data.Cookie[1:]
	return data, nil
}

func (f *Fetcher) StoreCookie(cookie []byte) {
	f.data.Cookie = append(f.data.Cookie, cookie)
}
