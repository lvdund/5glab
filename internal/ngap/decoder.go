package ngap

import (
	"fmt"
)

// NGAP PDU 
type NGAPPDU struct {
	ProcedureCode int64
	Criticality   int64
	Payload       []byte
}

// DownlinkNASTransport (AMF → UE)
type DownlinkNASTransport struct {
	RANUENGAPID int64
	AMFUENGAPID int64
	NASPdu      []byte
}

// InitialContextSetupRequest (AMF → UE)
type InitialContextSetupRequest struct {
	RANUENGAPID int64
	AMFUENGAPID int64
	NASPdu      []byte
}

// DecodeMessage
func DecodeMessage(buf []byte) (*NGAPPDU, error, interface{}) {
	if len(buf) < 3 {
		return nil, fmt.Errorf("buffer too short"), nil
	}


	procedureCode := int64(buf[1])

	pdu := &NGAPPDU{
		ProcedureCode: procedureCode,
		Criticality:   0,
		Payload:       buf,
	}

	switch procedureCode {
case 21: // DownlinkNASTransport      (p/s: có thể đoạn này đang sai)
	fmt.Printf("Decode DownlinkNASTransport raw: % X\n", buf)

	i := 5
	start := i + 1 

	if len(buf) < start+1 {
		return pdu, fmt.Errorf("DownlinkNASTransport too short"), nil
	}

	length := int(buf[i+4])<<8 | int(buf[i+3])

	var nasPdu []byte
	if start+length > len(buf) {
		fmt.Printf("NAS-PDU length mismatch: want %d, buffer only %d\n",
			length, len(buf)-start)
		nasPdu = buf[start:]
	} else {
		nasPdu = buf[start : start+length]
	}

	return pdu, nil, &DownlinkNASTransport{
		RANUENGAPID: 1,
		AMFUENGAPID: 1,
		NASPdu:      nasPdu,
	}

case 9: // InitialContextSetupRequest 
    return pdu, nil, &InitialContextSetupRequest{
        RANUENGAPID: 1,
        AMFUENGAPID: 1,
        NASPdu:      buf[3:],
    }
default:
    return pdu, nil, nil
}

}
