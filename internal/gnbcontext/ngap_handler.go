package gnbcontext

import (
	"fmt"
	"log"

	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/ies"
)

func (gnb *GnbContext) ngapHandler(ngapPdu []byte) {
	if len(ngapPdu) == 0 {
		log.Fatal("NGAP message is empty")
		return
	}

	ngapPduMsg, err, _ := ngap.NgapDecode(ngapPdu)
	if err != nil {
		log.Fatal("Error decoding NGAP message: %v", err)
	}

	// handle NGAP message.
	switch ngapPduMsg.Present {

	case ies.NgapPduInitiatingMessage:

		switch ngapPduMsg.Message.ProcedureCode.Value {

		case ies.ProcedureCode_DownlinkNASTransport:
			fmt.Println("Receive Downlink NAS Transport")
		default:
			fmt.Println("Received unknown NGAP message 0x%x", ngapPduMsg.Message.ProcedureCode.Value)
		}

	case ies.NgapPduSuccessfulOutcome:

		switch ngapPduMsg.Message.ProcedureCode.Value {

		case ies.ProcedureCode_NGSetup:
			fmt.Println("Receive NG Setup Response")
			gnb.AmgConnected = true

		default:
			fmt.Println("Received unknown NGAP message 0x%x", ngapPduMsg.Message.ProcedureCode.Value)
		}

	case ies.NgapPduUnsuccessfulOutcome:

		switch ngapPduMsg.Message.ProcedureCode.Value {

		case ies.ProcedureCode_NGSetup:
			fmt.Println("Receive Ng Setup Failure")

		default:
			fmt.Println("Received unknown NGAP message 0x%x", ngapPduMsg.Message.ProcedureCode.Value)
		}
	}
}
