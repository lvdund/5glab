package gnb

import (
	"log"

	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
)

func (gnb *Gnb) GetNgSetupRequest() []byte {
	msg := ies.NGSetupRequest{}
	msg.GlobalRANNodeID = ies.GlobalRANNodeID{
		Choice: ies.GlobalRANNodeIDPresentGlobalgnbId,
		GlobalGNBID: &ies.GlobalGNBID{
			PLMNIdentity: gnb.getMccAndMncInOctets(),
			GNBID: ies.GNBID{
				Choice: ies.GNBIDPresentGnbId,
				GNBID: &aper.BitString{
					Bytes:   gnb.getGnbIdInBytes(), // Example gNB ID: 0x00010203
					NumBits: 24,
				},
			},
		},
	}
	msg.SupportedTAList = []ies.SupportedTAItem{
		{
			TAC: gnb.getTacInBytes(), // TAC = 1
			BroadcastPLMNList: []ies.BroadcastPLMNItem{
				{
					PLMNIdentity: gnb.getMccAndMncInOctets(), // MCC=208, MNC=93
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

	//encode msg
	b, err := ngap.NgapEncode(&msg)
	if err != nil {
		log.Fatalf("Failed to encode")
		return nil
	}

	return b
}
