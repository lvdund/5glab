package ngap

import (
	"io"
)

type InitialUEMessage struct {
	NASPdu []byte
}

func (m InitialUEMessage) Encode(w io.Writer) error {
	_, err := w.Write(m.NASPdu)
	return err
}
