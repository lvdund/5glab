package gnb

import (
	"log"

	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
)

func (gnb *GNodeB) GetNgSetupRequest() []byte {
	msg := ies.NGSetupRequest{}
	msg.GlobalRANNodeID = ies.GlobalRANNodeID{
		Choice: ies.GlobalRANNodeIDPresentGlobalgnbId,
		GlobalGNBID: &ies.GlobalGNBID{
			PLMNIdentity: gnb.getMccAndMncInOctets(),
			GNBID: ies.GNBID{
				Choice: ies.GNBIDPresentGnbId,
				GNBID: &aper.BitString{
					Bytes:   gnb.getGnbIdInBytes(),
					NumBits: 24,
				},
			},
		},
	}
	msg.SupportedTAList = []ies.SupportedTAItem{
		{
			TAC: gnb.getTacInBytes(),
			BroadcastPLMNList: []ies.BroadcastPLMNItem{
				{
					PLMNIdentity: gnb.getMccAndMncInOctets(),
					TAISliceSupportList: []ies.SliceSupportItem{
						{
							SNSSAI: ies.SNSSAI{
								SST: []byte{0x01},             // SST = 1 (eMBB)
								SD:  []byte{0x11, 0x22, 0x33}, // SD = 0x11223
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
