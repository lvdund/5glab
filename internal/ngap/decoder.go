package ngap

import (
    "github.com/lvdund/ngap"
    "github.com/lvdund/ngap/ies"
)

func DecodeMessage(buf []byte) (*ngap.NgapPdu, error, interface{}) {
    pdu, err, _ := ngap.NgapDecode(buf)
    if err != nil {
        return nil, err, nil
    }

    payload := pdu.Message.Msg

    switch msg := payload.(type) {
    case *ies.DownlinkNASTransport:
        return &pdu, nil, msg
    default:
        return &pdu, nil, payload
    }
}
