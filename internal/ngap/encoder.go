package ngap

import (
	"bytes"
	ngaplib "github.com/lvdund/ngap"
)

func EncodeMessage(m ngaplib.NgapMessageEncoder) ([]byte, error) {
	var b bytes.Buffer
	if err := m.Encode(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
