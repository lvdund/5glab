package gnbcontext

import (
	"emulator/internal/sctp"
	"fmt"
	"log"
    "encoding/binary"

	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
)

type GnbContext struct {
	GnbId string
	Plmn  string
	Tac   uint32
	Ip    string
	Port  int

	AmfConnected bool

	sctpConn      *sctp.SctpConn
	NgapMsgChan   chan []byte
	RevUeMsgChan  chan []byte
	SendUeMsgChan chan []byte

	RanUeNgapId   uint64
	AmfUeNgapId   uint64
	initialSent   bool
	ueContextReady bool
	nasBuf         chan []byte
	UeUplinkChan chan []byte
     CellID uint32

}

// NewGnbContext
func NewGnbContext(
	gnbId, plmn, ip string,
	tac, port int,
	sctpConn *sctp.SctpConn,
	ngMsgChan, RevUeMsgChan, SendUeMsgChan chan []byte,
) *GnbContext {
	return &GnbContext{
		GnbId: gnbId,
		Plmn:  plmn,
		Tac:   uint32(tac),
		Ip:    ip,
		Port:  port,

		AmfConnected: false,

		RanUeNgapId:   1,
		AmfUeNgapId:   0,
		initialSent:   false,

		sctpConn:      sctpConn,
		NgapMsgChan:   ngMsgChan,
		RevUeMsgChan:  RevUeMsgChan,
		SendUeMsgChan: SendUeMsgChan,
		nasBuf:        make(chan []byte, 10),
		UeUplinkChan:  make(chan []byte, 10),
	}
}

func (g *GnbContext) GetNRCellIdentity() []byte {
	buf := make([]byte, 5) // NR Cell ID = 36 bits = 4.5 bytes, padding to 5
	binary.BigEndian.PutUint32(buf[0:4], g.CellID<<4) 
	return buf
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

// HandleNgapMsg process NGAP from AMF
func (gnb *GnbContext) HandleNgapMsg() {
	for msg := range gnb.NgapMsgChan {
		// decode & let handler extract AMF/RAN IDs and forward downlink NAS
		gnb.ngapHandler(msg, gnb.SendUeMsgChan, gnb.nasBuf)

		// Only mark UE context ready when AMF UE NGAP ID is known (non-zero)
		if gnb.initialSent && gnb.AmfUeNgapId != 0 && !gnb.ueContextReady {
			gnb.ueContextReady = true
			fmt.Printf("[gNB] AMF UE NGAP ID known (%d) → set ueContextReady = true and flush buffer\n", gnb.AmfUeNgapId)

			// flush buffered uplink NAS PDUs into UeUplinkChan for sending
			for {
				select {
				case pdu := <-gnb.nasBuf:
					select {
					case gnb.UeUplinkChan <- pdu:
					default:
						// channel full — requeue to avoid drop
						go func(b []byte) { gnb.nasBuf <- b }(pdu)
					}
				default:
					goto flushed
				}
			}
		flushed:
		}
	}
}


// HandlerUeNasMsg process NAS from UE → InitialUEMessage sends AMF
func (gnb *GnbContext) HandlerUeNasMsg() {
	for msg := range gnb.RevUeMsgChan {
		uli := ies.UserLocationInformation{
			Choice: ies.UserLocationInformationPresentUserlocationinformationnr,
			UserLocationInformationNR: &ies.UserLocationInformationNR{
				TAI: ies.TAI{
					PLMNIdentity: gnb.getMccAndMncInOctets(),
					TAC:          gnb.getTacInBytes(),
				},
				NRCGI: ies.NRCGI{
					PLMNIdentity: gnb.getMccAndMncInOctets(),
					NRCellIdentity: aper.BitString{
						Bytes:   []byte{0x11, 0x22, 0x33, 0x44, 0x55},
						NumBits: 36,
					},
				},
			},
		}

		if !gnb.initialSent {
			ngapMsg := ies.InitialUEMessage{
				RANUENGAPID:             int64(gnb.RanUeNgapId),
				NASPDU:                  msg,
				UserLocationInformation: uli,
				RRCEstablishmentCause:   ies.RRCEstablishmentCause{Value: 1},
				UEContextRequest:        &ies.UEContextRequest{},
			}

			buf, err := ngap.NgapEncode(&ngapMsg)
			if err != nil {
				log.Fatalf("Cannot encode InitialUEMessage: %v", err)
			}
			if err := gnb.sctpConn.Send(buf); err != nil {
				log.Fatalf("Failed to send InitialUEMessage: %v", err)
			}
			gnb.initialSent = true
			fmt.Println("Sent InitialUEMessage → AMF (PPID=60)")

		} else if gnb.ueContextReady {
			uplink := ies.UplinkNASTransport{
				RANUENGAPID:             int64(gnb.RanUeNgapId),
				AMFUENGAPID:             int64(gnb.AmfUeNgapId),
				NASPDU:                  msg,
				UserLocationInformation: uli,
			}

			buf, err := ngap.NgapEncode(&uplink)
			if err != nil {
				log.Fatalf("Cannot encode UplinkNASTransport: %v", err)
			}
			if err := gnb.sctpConn.Send(buf); err != nil {
				log.Fatalf("Failed to send UplinkNASTransport: %v", err)
			}
			fmt.Println("Sent UplinkNASTransport → AMF (PPID=60)")
		} else {
			// Buffer the uplink NAS PDU until AMF responded and we set ueContextReady
			fmt.Println("UE context chưa ready, buffer NAS PDU")
			select {
			case gnb.nasBuf <- msg:
				// buffered
			default:
				select {
				case <-gnb.nasBuf:
				default:
				}
				gnb.nasBuf <- msg
			}
		}
	}
}

// SendNgSetupRequest sends NG Setup Request to AMF
func (gnb *GnbContext) SendNgSetupRequest() error {
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

	msg := &ies.NGSetupRequest{
		GlobalRANNodeID:  globalRAN,
		SupportedTAList:  []ies.SupportedTAItem{supportedTA},
		DefaultPagingDRX: ies.PagingDRX{Value: 1},
	}

	ngapBuf, err := ngap.NgapEncode(msg)
	if err != nil {
		log.Printf("NGAP encode failed: %v", err)
		return err
	}

	if err := gnb.sctpConn.Send(ngapBuf); err != nil {
		return err
	}

	log.Println("NG Setup Request sent to AMF")
	return nil
}

func (gnb *GnbContext) HandleUeUplinkNAS() {
	for nasPdu := range gnb.UeUplinkChan {
		if !gnb.ueContextReady {
			fmt.Println("[gNB] UE context chưa ready, buffer NAS PDU")
			// push into nasBuf (non-blocking attempt)
			select {
			case gnb.nasBuf <- nasPdu:
			default:
				// if buffer full, discard oldest then push
				select {
				case <-gnb.nasBuf:
				default:
				}
				gnb.nasBuf <- nasPdu
			}
			continue
		}

		// UplinkNASTransport
		uplink := ies.UplinkNASTransport{
			RANUENGAPID: int64(gnb.RanUeNgapId),
			AMFUENGAPID: int64(gnb.AmfUeNgapId),
			NASPDU:      nasPdu,
		}

		buf, err := ngap.NgapEncode(&uplink)
		if err != nil {
			log.Printf("Cannot encode UplinkNASTransport: %v", err)
			continue
		}
		if err := gnb.sctpConn.Send(buf); err != nil {
			log.Printf("Failed to send UplinkNASTransport: %v", err)
			continue
		}
		fmt.Println("Sent UplinkNASTransport → AMF (PPID=60)")
	}
}












// 4/9/2025 
/*

func (gnb *GnbContext) getPLMNIdentity() []byte {
    // PLMN lưu trong gnb.Plmn dạng "20893" → MCC=208, MNC=93
    if len(gnb.Plmn) < 5 {
        return []byte{0x00, 0x00, 0x00}
    }
    mcc := gnb.Plmn[:3]
    mnc := gnb.Plmn[3:]

    // PLMN encoding theo 3GPP TS 24.008 BCD
    return []byte{
        byte((mcc[1]-'0')<<4 | (mcc[0]-'0')),
        byte((mnc[2]-'0')<<4 | (mcc[2]-'0')),
        byte((mnc[1]-'0')<<4 | (mnc[0]-'0')),
    }
}


func (gnb *GnbContext) getNRCellIdentity() []byte {
    // Ví dụ cellID=0xCAFE000 (20 bit), padding 36 bit
    return []byte{0xCA, 0xFE, 0x00, 0x00, 0x00}
}




func (gnb *GnbContext) buildUplinkNasTransport(nasPdu []byte) ([]byte, error) {
    fmt.Println("[gNB] Build UplinkNasTransport")

    msg := ies.UplinkNASTransport{}

    msg.AMFUENGAPID = int64(gnb.AmfUeNgapId)
    msg.RANUENGAPID = int64(gnb.RanUeNgapId)
    msg.NASPDU = nasPdu

    plmnid := gnb.getPLMNIdentity()
    cellid := gnb.getNRCellIdentity()
    tac := gnb.getTacInBytes()

    msg.UserLocationInformation = ies.UserLocationInformation{
    Choice: ies.UserLocationInformationPresentUserlocationinformationnr,
    UserLocationInformationNR: &ies.UserLocationInformationNR{
        NRCGI: ies.NRCGI{
            PLMNIdentity:   plmnid,
            NRCellIdentity: aper.BitString{
                Bytes:   cellid,
                NumBits: 36, // NRCellIdentity dài 36 bit
            },
        },
        TAI: ies.TAI{
            PLMNIdentity: plmnid,
            TAC:          tac,
        },
    },
}

    return ngap.NgapEncode(&msg)
}
*/