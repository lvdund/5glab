package gnbcontext

import (
	"emulator/internal/sctp"
	"fmt"
	"log"

	gosctp "github.com/ishidawataru/sctp"
	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
)

// GnbContext
type GnbContext struct {
	GnbId string
	Plmn  string
	Tac   uint32
	Ip    string
	Port  int

	AmgConnected bool

	sctpConn      *sctp.SctpConn
	NgapMsgChan   chan []byte // store ngap from AMF
	RevUeMsgChan  chan []byte // store msg from UE
	SendUeMsgChan chan []byte // send nas msg to UE
}

func NewGnbContext(gnbId, plmn, ip string, tac, port int, sctpConn *sctp.SctpConn, ngMsgChan, RevUeMsgChan, SendUeMsgChan chan []byte) *GnbContext {
	return &GnbContext{
		GnbId: gnbId,
		Plmn:  plmn,
		Tac:   uint32(tac),
		Ip:    ip,
		Port:  port,

		AmgConnected: false,

		sctpConn:      sctpConn,
		NgapMsgChan:   ngMsgChan,
		RevUeMsgChan:  RevUeMsgChan,
		SendUeMsgChan: SendUeMsgChan,
	}
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
		((mnc2)<<4 | (mcc[2] - '0')),
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

func (gnb *GnbContext) HandleNgapMsg() {
	for msg := range gnb.NgapMsgChan {
		gnb.ngapHandler(msg)
	}
}

func (gnb *GnbContext) HandlerUeNasMsg() {
	for msg := range gnb.RevUeMsgChan {

		//NOTE: InitialUEMessage just for 1st step init ue connect to AMF
		// you have to implement UPLinkNasTransport

		ngapMsg := ies.InitialUEMessage{
			RANUENGAPID:             1, //Check
			NASPDU:                  msg,
			UserLocationInformation: ies.UserLocationInformation{},
			RRCEstablishmentCause:   ies.RRCEstablishmentCause{},
			UEContextRequest:        &ies.UEContextRequest{},
		}

		buf, err := ngap.NgapEncode(&ngapMsg)
		if err != nil {
			log.Fatal("Cannot encode InitialUEMessage")
			continue
		}

		if err := gnb.sctpConn.Send(buf); err != nil {
			log.Fatalf("Failed to send: %v", err)
		}
		fmt.Println("Sent InitialUEMessage → AMF (PPID=60)")
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
	err = gnb.sctpConn.Send(ngapBuf)
	if err != nil {
		return err
	}

	log.Println("NG Setup Request sent to AMF")
	return nil
}
