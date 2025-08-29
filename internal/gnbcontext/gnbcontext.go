package gnbcontext

import (
	"log"

	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
	gosctp "github.com/ishidawataru/sctp"
)

// GnbContext
type GnbContext struct {
	GnbId string
	Plmn  string
	Tac   uint32 
	Ip    string
	Port  int
}

// convert PLMN string -> 3 bytes 
func (gnb *GnbContext) getMccAndMncInOctets() []byte {
	if len(gnb.Plmn) < 5 || len(gnb.Plmn) > 6 {
		log.Fatalf("Invalid PLMN length: %s", gnb.Plmn)
	}
	mcc := gnb.Plmn[:3]
	mnc := gnb.Plmn[3:]

	var mnc0, mnc1, mnc2 byte
	if len(mnc) == 2 {
		mnc0 = mnc[0] - '0'
		mnc1 = mnc[1] - '0'
		mnc2 = 0xF
	} else {
		mnc0 = mnc[0] - '0'
		mnc1 = mnc[1] - '0'
		mnc2 = mnc[2] - '0'
	}

	return []byte{
		((mcc[1]-'0')<<4 | (mcc[0] - '0')), 
		((mnc2)<<4 | (mcc[2]-'0')),        
		((mnc1)<<4 | (mnc0)),               
	}
}

// convert GNBID -> 3 bytes
func (gnb *GnbContext) getGnbIdInBytes() []byte {
	return []byte{0x01, 0x02, 0x03}
}

// convert TAC -> 3 bytes
func (gnb *GnbContext) getTacInBytes() []byte {
	return []byte{
		byte((gnb.Tac >> 16) & 0xff),
		byte((gnb.Tac >> 8) & 0xff),
		byte(gnb.Tac & 0xff),
	}
}

// NG Setup Request
func (gnb *GnbContext) SendNgSetupRequest(conn *gosctp.SCTPConn) error {
	globalRAN := ies.GlobalRANNodeID{
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

	// SupportedTAList
	supportedTA := ies.SupportedTAItem{
		TAC: gnb.getTacInBytes(), 
		BroadcastPLMNList: []ies.BroadcastPLMNItem{
			{
				PLMNIdentity: gnb.getMccAndMncInOctets(),
				TAISliceSupportList: []ies.SliceSupportItem{
					{
						SNSSAI: ies.SNSSAI{
							SST: []byte{0x01},             
							SD:  []byte{0x01, 0x02, 0x03}, 
						},
					},
					{
						SNSSAI: ies.SNSSAI{
							SST: []byte{0x01},
							SD:  []byte{0x11, 0x22, 0x33},
						},
					},
				},
			},
		},
	}

	// NGSetupRequest message 
	msg := &ies.NGSetupRequest{
		GlobalRANNodeID:  globalRAN,
		SupportedTAList:  []ies.SupportedTAItem{supportedTA},
		DefaultPagingDRX: ies.PagingDRX{Value: 1},
	}

	// encode NGAP 
	ngapBuf, err := ngap.NgapEncode(msg)
	if err != nil {
		log.Printf("NGAP encode failed: %v", err)
		return err
	}

	// SCTP write 
	info := &gosctp.SndRcvInfo{Stream: 0, PPID: 60}
	_, err = conn.SCTPWrite(ngapBuf, info)
	if err != nil {
		log.Printf("Failed to send NG Setup Request: %v", err)
		return err
	}

	log.Println("NG Setup Request sent to AMF")
	return nil
}
