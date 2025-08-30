package internal

import (
	"fmt"
	"log"
	"net"

	"github.com/ishidawataru/sctp"
	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
)

func main() {
	amfAddr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.ParseIP("192.168.56.3")}},
		Port:    38412,
	}

	conn, err := sctp.DialSCTP("sctp", nil, amfAddr)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	fmt.Println("gnb connected to the AMF")

	msg := ies.NGSetupRequest{}
	msg.GlobalRANNodeID = ies.GlobalRANNodeID{
		Choice: ies.GlobalRANNodeIDPresentGlobalgnbId,
		GlobalGNBID: &ies.GlobalGNBID{
			PLMNIdentity: []byte{0x20, 0xF8, 0x39}, // MCC=208, MNC=93 (Free5GC default),
			GNBID: ies.GNBID{
				Choice: ies.GNBIDPresentGnbId,
				GNBID: &aper.BitString{
					Bytes:   []byte{0x00, 0x01, 0x02}, // Example gNB ID: 0x00010203
					NumBits: 24,
				},
			},
		},
	}
	msg.SupportedTAList = []ies.SupportedTAItem{
		{
			TAC: []byte{0x00, 0x00, 0x01}, // TAC = 1
			BroadcastPLMNList: []ies.BroadcastPLMNItem{
				{
					PLMNIdentity: []byte{0x20, 0xF8, 0x39}, // MCC=208, MNC=93
					TAISliceSupportList: []ies.SliceSupportItem{
						{
							SNSSAI: ies.SNSSAI{
								SST: []byte{0x01},             // SST = 1 (eMBB)
								SD:  []byte{0x11, 0x22, 0x33}, // SD = 0x112233
							},
						},
					},
				},
			},
		},
	}
	msg.DefaultPagingDRX = ies.PagingDRX{Value: ies.PagingDRXV128}

	ngapPdu, err := ngap.NgapEncode(&msg)
	if err != nil {
		fmt.Printf("Error sending NG set up request ", err)
	}
	//amf.sendNgap(ngapPdu)

}
