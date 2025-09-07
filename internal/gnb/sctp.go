package gnb

import (
	"fmt"
	"log"

	"github.com/Phuc12012005/emulator/internal/ue"
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

		handleNgap(pdu, conn)
	}
}

func handleNgap(ngapPduMsg ngap.NgapPdu, conn *sctp.SCTPConn) {
	// handle NGAP message.
	switch ngapPduMsg.Present {

	case ies.NgapPduInitiatingMessage:

		switch ngapPduMsg.Message.ProcedureCode.Value {

		case ies.ProcedureCode_DownlinkNASTransport:
			fmt.Printf("Receive Downlink NAS Transport\n")
		default:
			fmt.Printf("Received unknown NGAP message 0x%x", ngapPduMsg.Message.ProcedureCode.Value)
		}

	case ies.NgapPduSuccessfulOutcome:

		switch ngapPduMsg.Message.ProcedureCode.Value {

		case ies.ProcedureCode_NGSetup:
			fmt.Println("Receive NG Setup Response")

			// Create UE
			ueCtx := ue.NewUserEquipment("imsi-208930000000001", "20893", 1, "208", "93")

			// Build NAS Registration Request
			nasPdu, err := BuildRegistrationRequest(ueCtx)
			if err != nil {
				fmt.Println("Failed to build NAS Registration Request:", err)
				return
			}

			// Wrap in InitialUEMessage
			initialUeMsg, err := BuildInitialUeMessage(nasPdu)
			if err != nil {
				fmt.Println("Failed to build InitialUEMessage:", err)
				return
			}

			SctpWrite(initialUeMsg, conn)
			fmt.Println("Sent InitialUEMessage with Registration Request")

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
