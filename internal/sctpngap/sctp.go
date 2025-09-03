package sctpngap

import (
	"fmt"
	"log"

	"github.com/ishidawataru/sctp"
	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/ies"
)

func SctpListen(conn *sctp.SCTPConn) {
	for {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)

		if err != nil {
			log.Fatalln("read failed ", err)
		}
		fmt.Printf("Got %v bytes from AMF\n", n)

		response := buf[:n]
		var pdu ngap.NgapPdu
		pdu, err, _ = ngap.NgapDecode(response)
		if err != nil {
			log.Fatalf("decode NGSetupResponse failed: %v", err)
		}

		handleNgap(pdu)
	}
}

func handleNgap(ngapPduMsg ngap.NgapPdu) {
	// handle NGAP message.
	switch ngapPduMsg.Present {

	case ies.NgapPduInitiatingMessage:

		switch ngapPduMsg.Message.ProcedureCode.Value {

		case ies.ProcedureCode_DownlinkNASTransport:
			fmt.Printf("Receive Downlink NAS Transport")
		default:
			fmt.Printf("Received unknown NGAP message 0x%x", ngapPduMsg.Message.ProcedureCode.Value)
		}

	case ies.NgapPduSuccessfulOutcome:

		switch ngapPduMsg.Message.ProcedureCode.Value {

		case ies.ProcedureCode_NGSetup:
			fmt.Println("Receive NG Setup Response")

		default:
			fmt.Printf("Received unknown NGAP message 0x%x", ngapPduMsg.Message.ProcedureCode.Value)
		}

	case ies.NgapPduUnsuccessfulOutcome:

		switch ngapPduMsg.Message.ProcedureCode.Value {

		case ies.ProcedureCode_NGSetup:
			fmt.Println("Receive Ng Setup Failure")

		default:
			fmt.Printf("Received unknown NGAP message 0x%x", ngapPduMsg.Message.ProcedureCode.Value)
		}
	}
}

func SctpWrite(pdu []byte, conn *sctp.SCTPConn) {
	info := &sctp.SndRcvInfo{
		Stream: uint16(0),
		PPID:   uint32(60),
	}
	_, err := conn.SCTPWrite(pdu, info)
	if err != nil {
		fmt.Println("Error sending NGAP message ", err)
	}
}
