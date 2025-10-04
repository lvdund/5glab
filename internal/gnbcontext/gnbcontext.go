package gnbcontext

import (
	"encoding/binary"
	"fmt"
	"log"

	"emulator/internal/sctp"

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
	UeUplinkChan   chan []byte
	CellID         uint32
}

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
	buf := make([]byte, 5) // 36 bit = 4.5 byte → padding 5 byte
	binary.BigEndian.PutUint32(buf[0:4], g.CellID<<4)
	return buf
}

// convert PLMN string -> 3 bytes (MCC+MNC)
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
	return []byte{0x01, 0x02, 0x03} // bạn có thể convert thực tế từ gnb.GnbId
}

// convert TAC -> 3 bytes
func (gnb *GnbContext) getTacInBytes() []byte {
	return []byte{
		byte((gnb.Tac >> 16) & 0xff),
		byte((gnb.Tac >> 8) & 0xff),
		byte(gnb.Tac & 0xff),
	}
}

// --- NGAP Handler ---

func (gnb *GnbContext) HandleNgapMsg() {
	for msg := range gnb.NgapMsgChan {
		fmt.Printf("[gNB] HandleNgapMsg: received NGAP msg len=%d\n", len(msg))
		fmt.Printf("[gNB] current state: initialSent=%v, AmfUeNgapId=%d, ueContextReady=%v\n",
			gnb.initialSent, gnb.AmfUeNgapId, gnb.ueContextReady)

		// Decode NGAP message
		pdu, err, _ := ngap.NgapDecode(msg)
		if err != nil {
			fmt.Printf("[gNB] NGAP decode error: %v\n", err)
			continue
		}

		switch pdu.Present {
		case ies.NgapPduSuccessfulOutcome:
			// NG Setup Response
			if _, ok := pdu.Message.Msg.(*ies.NGSetupResponse); ok {
				fmt.Printf("[gNB] Received NG Setup Response from AMF\n")
				gnb.AmfConnected = true
			}

		case ies.NgapPduInitiatingMessage:
			switch pdu.Message.ProcedureCode.Value {
			
			case ies.ProcedureCode_DownlinkNASTransport:
				fmt.Println("[gNB] Receive Downlink NAS Transport")
				if downlink, ok := pdu.Message.Msg.(*ies.DownlinkNASTransport); ok {
					// Update IDs
					if downlink.AMFUENGAPID != 0 {
						gnb.AmfUeNgapId = uint64(downlink.AMFUENGAPID)
						fmt.Printf("[gNB] Learned AMF UE NGAP ID: %d\n", gnb.AmfUeNgapId)
					}
					if downlink.RANUENGAPID != 0 {
						gnb.RanUeNgapId = uint64(downlink.RANUENGAPID)
					}

					// UE context ready after receiving first downlink
					if !gnb.ueContextReady {
						gnb.ueContextReady = true
					}

					// Forward NAS PDU to UE
					nas := nasToBytes(downlink.NASPDU)
					if len(nas) > 0 {
						fmt.Printf("[gNB] Forward NAS → UE (%d bytes)\n", len(nas))
						select {
						case gnb.SendUeMsgChan <- nas:
							fmt.Println("[gNB] Forwarded NAS PDU to UE")
						default:
							fmt.Println("[gNB] SendUeMsgChan full, cannot forward NAS PDU")
						}
					}
				}

			case ies.ProcedureCode_InitialContextSetup:
				fmt.Println("[gNB] ========== Receive InitialContextSetupRequest ==========")
				if icsReq, ok := pdu.Message.Msg.(*ies.InitialContextSetupRequest); ok {
					// Update IDs
					if icsReq.AMFUENGAPID != 0 {
						gnb.AmfUeNgapId = uint64(icsReq.AMFUENGAPID)
						fmt.Printf("[gNB] Set AMF_UE_NGAP_ID=%d\n", gnb.AmfUeNgapId)
					}
					if icsReq.RANUENGAPID != 0 {
						gnb.RanUeNgapId = uint64(icsReq.RANUENGAPID)
						fmt.Printf("[gNB] Set RAN_UE_NGAP_ID=%d\n", gnb.RanUeNgapId)
					}

					// Mark UE context as ready
					gnb.ueContextReady = true

					// Extract and forward NAS-PDU (Registration Accept)
					nas := nasToBytes(icsReq.NASPDU)
					if len(nas) > 0 {
						fmt.Printf("[gNB] Forward NAS (Registration Accept) → UE (%d bytes): %x\n", len(nas), nas)
						select {
						case gnb.SendUeMsgChan <- nas:
							fmt.Println("[gNB] Successfully forwarded Registration Accept to UE")
						default:
							fmt.Println("[gNB] ERROR: SendUeMsgChan full, cannot forward Registration Accept")
						}
					} else {
						fmt.Println("[gNB] WARNING: No NAS-PDU in InitialContextSetupRequest")
					}

					// Send Initial Context Setup Response back to AMF
					go gnb.sendInitialContextSetupResponse()
				}

			case ies.ProcedureCode_ErrorIndication:
				if errInd, ok := pdu.Message.Msg.(*ies.ErrorIndication); ok {
					fmt.Printf("[gNB] ErrorIndication from AMF: AMFUENGAPID=%v, RANUENGAPID=%v, Cause=%v\n",
						errInd.AMFUENGAPID, errInd.RANUENGAPID, errInd.Cause)
				}

			default:
				fmt.Printf("[gNB] Unhandled Initiating Message, ProcedureCode=%d\n", 
					pdu.Message.ProcedureCode.Value)
			}

		case ies.NgapPduUnsuccessfulOutcome:
			if pdu.Message.ProcedureCode.Value == ies.ProcedureCode_NGSetup {
				fmt.Println("[gNB] Receive NG Setup Failure")
				gnb.AmfConnected = false
			}

		default:
			fmt.Printf("[gNB] Unknown NGAP PDU present: %d\n", pdu.Present)
		}

		// Flush buffered NAS PDUs if context just became ready
		if gnb.initialSent && gnb.AmfUeNgapId != 0 && gnb.ueContextReady {
			gnb.flushNasBuffer()
		}
	}
}

// Send Initial Context Setup Response
func (gnb *GnbContext) sendInitialContextSetupResponse() {
	if gnb.AmfUeNgapId == 0 || gnb.RanUeNgapId == 0 {
		log.Printf("[gNB] Cannot send ICS Response: AMF_ID=%d, RAN_ID=%d", 
			gnb.AmfUeNgapId, gnb.RanUeNgapId)
		return
	}

	response := &ies.InitialContextSetupResponse{
		AMFUENGAPID: int64(gnb.AmfUeNgapId),
		RANUENGAPID: int64(gnb.RanUeNgapId),
		// PDU Session Resource Setup Response List - empty for now
	}

	buf, err := ngap.NgapEncode(response)
	if err != nil {
		log.Printf("[gNB] Failed to encode InitialContextSetupResponse: %v", err)
		return
	}

	if err := gnb.sctpConn.Send(buf); err != nil {
		log.Printf("[gNB] Failed to send InitialContextSetupResponse: %v", err)
		return
	}

	fmt.Println("[gNB] ========== Sent InitialContextSetupResponse → AMF ==========")
}

// Flush buffered NAS PDUs
func (gnb *GnbContext) flushNasBuffer() {
	flushed := 0
	for {
		select {
		case pdu := <-gnb.nasBuf:
			gnb.UeUplinkChan <- pdu
			flushed++
		default:
			if flushed > 0 {
				fmt.Printf("[gNB] Flushed %d buffered NAS PDUs\n", flushed)
			}
			return
		}
	}
}

func (gnb *GnbContext) HandlerUeNasMsg() {
	for msg := range gnb.RevUeMsgChan {
		if !gnb.initialSent {
			fmt.Println("[gNB] Sending InitialUEMessage")
			ngapMsg := ies.InitialUEMessage{
				RANUENGAPID: int64(gnb.RanUeNgapId),
				NASPDU:      msg,
				UserLocationInformation: ies.UserLocationInformation{
					Choice: ies.UserLocationInformationPresentUserlocationinformationnr,
					UserLocationInformationNR: &ies.UserLocationInformationNR{
						NRCGI: ies.NRCGI{
							PLMNIdentity: gnb.getMccAndMncInOctets(),
							NRCellIdentity: aper.BitString{
								Bytes:   gnb.GetNRCellIdentity(),
								NumBits: 36,
							},
						},
						TAI: ies.TAI{
							PLMNIdentity: gnb.getMccAndMncInOctets(),
							TAC:          gnb.getTacInBytes(),
						},
					},
				},
				RRCEstablishmentCause: ies.RRCEstablishmentCause{Value: 1},
				UEContextRequest:      &ies.UEContextRequest{Value: ies.UEContextRequestRequested},
			}

			buf, err := ngap.NgapEncode(&ngapMsg)
			if err != nil {
				log.Fatalf("Cannot encode InitialUEMessage: %v", err)
			}
			if err := gnb.sctpConn.Send(buf); err != nil {
				log.Fatalf("Failed to send InitialUEMessage: %v", err)
			}
			gnb.initialSent = true
			fmt.Println("================================[gNB] Sent InitialUEMessage → AMF (PPID=60)")

		} else if gnb.ueContextReady {
			fmt.Println("[gNB] Sending UplinkNASTransport")
			uplink := ies.UplinkNASTransport{
				RANUENGAPID: int64(gnb.RanUeNgapId),
				AMFUENGAPID: int64(gnb.AmfUeNgapId),
				NASPDU:      msg,
				UserLocationInformation: ies.UserLocationInformation{
					Choice: ies.UserLocationInformationPresentUserlocationinformationnr,
					UserLocationInformationNR: &ies.UserLocationInformationNR{
						NRCGI: ies.NRCGI{
							PLMNIdentity: gnb.getMccAndMncInOctets(),
							NRCellIdentity: aper.BitString{
								Bytes:   gnb.GetNRCellIdentity(),
								NumBits: 36,
							},
						},
						TAI: ies.TAI{
							PLMNIdentity: gnb.getMccAndMncInOctets(),
							TAC:          gnb.getTacInBytes(),
						},
					},
				},
			}

			buf, err := ngap.NgapEncode(&uplink)
			if err != nil {
				log.Fatalf("Cannot encode UplinkNASTransport: %v", err)
			}
			if err := gnb.sctpConn.Send(buf); err != nil {
				log.Fatalf("Failed to send UplinkNASTransport: %v", err)
			}
			fmt.Println("[gNB] Sent UplinkNASTransport → AMF (PPID=60)")

		} else {
			fmt.Println("[gNB] UE context chưa ready, buffer NAS PDU")
			select {
			case gnb.nasBuf <- msg:
			default:
				select { case <-gnb.nasBuf: default: }
				gnb.nasBuf <- msg
			}
		}
	}
}

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
					{SNSSAI: ies.SNSSAI{SST: []byte{0x01}, SD: []byte{0x01, 0x02, 0x03}}},
					{SNSSAI: ies.SNSSAI{SST: []byte{0x01}, SD: []byte{0x11, 0x22, 0x33}}},
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

	log.Println("========================================NG Setup Request sent to AMF")
	return nil
}

func (gnb *GnbContext) HandleUeUplinkNAS() {
	for nasPdu := range gnb.UeUplinkChan {
		if !gnb.ueContextReady {
			select {
			case gnb.nasBuf <- nasPdu:
			default:
				select { case <-gnb.nasBuf: default: }
				gnb.nasBuf <- nasPdu
			}
			continue
		}

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
		fmt.Println("[gNB] Sent UplinkNASTransport → AMF (PPID=60)")
	}
}
