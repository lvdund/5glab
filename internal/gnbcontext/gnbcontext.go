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
	gnbIdBytes := make([]byte, 3)
	
	if len(gnb.GnbId) >= 6 {
		// Parse hex string like "000001" or "000009"
		for i := 0; i < 3; i++ {
			fmt.Sscanf(gnb.GnbId[i*2:i*2+2], "%02x", &gnbIdBytes[i])
		}
	} else {
		// Fallback for shorter strings
		gnbIdBytes = []byte{0x00, 0x00, 0x09}
	}
	
	return gnbIdBytes
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
		fmt.Printf("[gNB] HandleNgapMsg: received NGAP msg len=%d\n", len(msg))
		fmt.Printf("[gNB] current state: initialSent=%v, AmfUeNgapId=%d, ueContextReady=%v\n",
			gnb.initialSent, gnb.AmfUeNgapId, gnb.ueContextReady)

		// Decode NGAP message
		pdu, err, _ := ngap.NgapDecode(msg)
		if err != nil {
			fmt.Printf("[gNB] NGAP decode error: %v\n", err)
			continue
		}

		// ======================= MAIN SWITCH =======================
		switch pdu.Present {
		// ======================= SUCCESSFUL OUTCOME =======================
		case ies.NgapPduSuccessfulOutcome:
			// NG Setup Response
			if pdu.Message.ProcedureCode.Value == ies.ProcedureCode_NGSetup {
				if _, ok := pdu.Message.Msg.(*ies.NGSetupResponse); ok {
					fmt.Printf("[gNB] Received NG Setup Response from AMF\n")
					gnb.AmfConnected = true
				}
			} else if pdu.Message.ProcedureCode.Value == ies.ProcedureCode_HandoverPreparation {
				// Handover Command (Successful Outcome)
				fmt.Println("[gNB] ========== Received Handover Command ==========")
				if hoCmd, ok := pdu.Message.Msg.(*ies.HandoverCommand); ok {
					fmt.Printf("[gNB] RAN UE NGAP ID: %d\n", hoCmd.RANUENGAPID)
					fmt.Printf("[gNB] AMF UE NGAP ID: %d\n", hoCmd.AMFUENGAPID)
					gnb.handlerHandoverCommand(hoCmd)
				} else {
					fmt.Printf("[gNB] Failed to cast to HandoverCommand, actual type: %T\n", pdu.Message.Msg)
				}
			}

		// ======================= INITIATING MESSAGE =======================
		case ies.NgapPduInitiatingMessage:
			fmt.Printf("[gNB] Initiating Message - ProcedureCode: %d\n", pdu.Message.ProcedureCode.Value)

			switch pdu.Message.ProcedureCode.Value {
			case ies.ProcedureCode_DownlinkNASTransport:
				fmt.Println("[gNB] Receive Downlink NAS Transport")
				if downlink, ok := pdu.Message.Msg.(*ies.DownlinkNASTransport); ok {
					if downlink.AMFUENGAPID != 0 {
						gnb.AmfUeNgapId = uint64(downlink.AMFUENGAPID)
						fmt.Printf("[gNB] Learned AMF UE NGAP ID: %d\n", gnb.AmfUeNgapId)
					}
					if downlink.RANUENGAPID != 0 {
						gnb.RanUeNgapId = uint64(downlink.RANUENGAPID)
					}

					if !gnb.ueContextReady {
						gnb.ueContextReady = true
					}

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
					if icsReq.AMFUENGAPID != 0 {
						gnb.AmfUeNgapId = uint64(icsReq.AMFUENGAPID)
						fmt.Printf("[gNB] Set AMF_UE_NGAP_ID=%d\n", gnb.AmfUeNgapId)
					}
					if icsReq.RANUENGAPID != 0 {
						gnb.RanUeNgapId = uint64(icsReq.RANUENGAPID)
						fmt.Printf("[gNB] Set RAN_UE_NGAP_ID=%d\n", gnb.RanUeNgapId)
					}

					gnb.ueContextReady = true

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

					go gnb.sendInitialContextSetupResponse()
				}

			case ies.ProcedureCode_PDUSessionResourceSetup:
				fmt.Println("[gNB] Receive PDU Session Resource Setup Request")
				if pduSessionReq, ok := pdu.Message.Msg.(*ies.PDUSessionResourceSetupRequest); ok {
					gnb.handlerPduSessionResourceSetupRequest(pduSessionReq)
				}

			case ies.ProcedureCode_PDUSessionResourceRelease:
				fmt.Println("[gNB] Receive PDU Session Resource Release Command")
				if pduSessionRel, ok := pdu.Message.Msg.(*ies.PDUSessionResourceReleaseCommand); ok {
					gnb.handlerPduSessionReleaseCommand(pduSessionRel)
				}

			case ies.ProcedureCode_HandoverResourceAllocation:
				fmt.Println("[gNB] ========== Receive Handover Request ==========")
				if hoReq, ok := pdu.Message.Msg.(*ies.HandoverRequest); ok {
					gnb.handlerHandoverRequest(hoReq)
				} else {
					fmt.Printf("[gNB] Failed to cast to HandoverRequest, actual type: %T\n", pdu.Message.Msg)
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

		// ======================= UNSUCCESSFUL OUTCOME =======================
		case ies.NgapPduUnsuccessfulOutcome:
			fmt.Printf("[gNB] Unsuccessful Outcome - ProcedureCode: %d\n", pdu.Message.ProcedureCode.Value)

			if pdu.Message.ProcedureCode.Value == ies.ProcedureCode_NGSetup {
				fmt.Println("[gNB] Receive NG Setup Failure")
				gnb.AmfConnected = false
			} else if pdu.Message.ProcedureCode.Value == ies.ProcedureCode_HandoverPreparation {
				fmt.Println("[gNB] ========== Receive Handover Preparation Failure ==========")
				if hoFailure, ok := pdu.Message.Msg.(*ies.HandoverPreparationFailure); ok {
					fmt.Printf("[gNB] Handover failed\n")
					fmt.Printf("[gNB]   RAN UE NGAP ID: %d\n", hoFailure.RANUENGAPID)
					fmt.Printf("[gNB]   AMF UE NGAP ID: %d\n", hoFailure.AMFUENGAPID)
					if hoFailure.Cause.RadioNetwork != nil {
						fmt.Printf("[gNB]   Cause (Radio Network): %d\n", hoFailure.Cause.RadioNetwork.Value)
					} else if hoFailure.Cause.Transport != nil {
						fmt.Printf("[gNB]   Cause (Transport): %d\n", hoFailure.Cause.Transport.Value)
					} else if hoFailure.Cause.Nas != nil {
						fmt.Printf("[gNB]   Cause (NAS): %d\n", hoFailure.Cause.Nas.Value)
					} else if hoFailure.Cause.Protocol != nil {
						fmt.Printf("[gNB]   Cause (Protocol): %d\n", hoFailure.Cause.Protocol.Value)
					} else if hoFailure.Cause.Misc != nil {
						fmt.Printf("[gNB]   Cause (Misc): %d\n", hoFailure.Cause.Misc.Value)
					}
				} else {
					fmt.Printf("[gNB] Failed to cast to HandoverPreparationFailure, actual type: %T\n", pdu.Message.Msg)
				}
			}

		default:
			fmt.Printf("[gNB] Unknown NGAP PDU present: %d\n", pdu.Present)
		}

		// ======================= FLUSH NAS BUFFER =======================
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
			fmt.Println("================[gNB] Sent InitialUEMessage → AMF (PPID=60)=============================")

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

	log.Println("====================NG Setup Request sent to AMF===============================")
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



// ============================================================================
// Hàm handlerPduSessionResourceSetupRequest 
// ============================================================================

func (gnb *GnbContext) handlerPduSessionResourceSetupRequest(msg *ies.PDUSessionResourceSetupRequest) {
   ranUeId := msg.RANUENGAPID
   amfUeId := msg.AMFUENGAPID
   var pDUSessionResourceSetupList []ies.PDUSessionResourceSetupItemSUReq


   if msg.PDUSessionResourceSetupListSUReq == nil {
       fmt.Println("[gNB] ERROR: PDU SESSION RESOURCE SETUP LIST SU REQ is missing")
       return
   } else {
       pDUSessionResourceSetupList = msg.PDUSessionResourceSetupListSUReq
   }


   // Update IDs
   if amfUeId != 0 {
       gnb.AmfUeNgapId = uint64(amfUeId)
       fmt.Printf("[gNB] Set AMF_UE_NGAP_ID=%d\n", gnb.AmfUeNgapId)
   }
   if ranUeId != 0 {
       gnb.RanUeNgapId = uint64(ranUeId)
       fmt.Printf("[gNB] Set RAN_UE_NGAP_ID=%d\n", gnb.RanUeNgapId)
   }


   var setupSuccessList []ies.PDUSessionResourceSetupItemSURes


   for _, item := range pDUSessionResourceSetupList {
       var pduSessionId int64
       var ulTeid uint32
       var upfAddress []byte
       var messageNas []byte
       var sst string
       var sd string


       // Get NAS PDU
       if item.PDUSessionNASPDU != nil {
           messageNas = item.PDUSessionNASPDU
       } else {
           fmt.Println("[gNB] WARNING: NAS PDU is missing")
       }


       pduSessionId = int64(item.PDUSessionID)


       if item.SNSSAI.SD != nil {
           sd = fmt.Sprintf("%02x%02x%02x", item.SNSSAI.SD[0], item.SNSSAI.SD[1], item.SNSSAI.SD[2])
       } else {
           sd = "not informed"
       }


       if item.SNSSAI.SST != nil {
           sst = fmt.Sprintf("%02x", item.SNSSAI.SST[0])
       } else {
           sst = "not informed"
       }


       if item.PDUSessionResourceSetupRequestTransfer != nil {
           pDUSessionResourceSetupRequestTransfer := &ies.PDUSessionResourceSetupRequestTransfer{}
           if err, _ := pDUSessionResourceSetupRequestTransfer.Decode(item.PDUSessionResourceSetupRequestTransfer); err == nil {
               ulTeid = binary.BigEndian.Uint32(pDUSessionResourceSetupRequestTransfer.ULNGUUPTNLInformation.GTPTunnel.GTPTEID)
               upfAddress = pDUSessionResourceSetupRequestTransfer.ULNGUUPTNLInformation.GTPTunnel.TransportLayerAddress.Bytes
           } else {
               fmt.Println("[gNB] Error in decode Pdu Session Resource Setup Request Transfer")
           }
       } else {
           fmt.Println("[gNB] ERROR: Pdu Session Resource Setup Request Transfer is missing")
       }


       upfIp := fmt.Sprintf("%d.%d.%d.%d", upfAddress[0], upfAddress[1], upfAddress[2], upfAddress[3])


       fmt.Println("[gNB] PDU Session was created with successful.")
       fmt.Printf("[gNB] PDU Session Id: %d\n", pduSessionId)
       fmt.Printf("[gNB] \tNSSAI Selected --- sst:%s sd:%s\n", sst, sd)
       fmt.Printf("[gNB] \tUplink Teid: 0x%08x\n", ulTeid)
       fmt.Printf("[gNB] \tUPF Address: %s:2152\n", upfIp)


       // Forward NAS message to UE
       if len(messageNas) > 0 {
           fmt.Printf("[gNB] Forwarding NAS PDU to UE (%d bytes)\n", len(messageNas))
           select {
           case gnb.SendUeMsgChan <- messageNas:
               fmt.Println("[gNB] NAS PDU forwarded to UE")
           default:
               fmt.Println("[gNB] SendUeMsgChan full, cannot forward NAS PDU")
           }
       }


       // Build response transfer
       responseTransfer := gnb.getPDUSessionResourceSetupResponseTransfer(pduSessionId)
      
       successItem := ies.PDUSessionResourceSetupItemSURes{
           PDUSessionID: item.PDUSessionID,
           PDUSessionResourceSetupResponseTransfer: responseTransfer,
       }
       setupSuccessList = append(setupSuccessList, successItem)
   }


   // Send PDU Session Resource Setup Response
   gnb.sendPduSessionResourceSetupResponse(setupSuccessList, ranUeId, amfUeId)
}


// getPDUSessionResourceSetupResponseTransfer 
func (gnb *GnbContext) getPDUSessionResourceSetupResponseTransfer(pduSessionId int64) []byte {
   data := ies.PDUSessionResourceSetupResponseTransfer{}

   dlTeid := uint32(0x00000001)
   dowlinkTeid := make([]byte, 4)
   binary.BigEndian.PutUint32(dowlinkTeid, dlTeid)


   gnbIp := []byte{192, 168, 1, 10}
  
   data.DLQosFlowPerTNLInformation = ies.QosFlowPerTNLInformation{
       UPTransportLayerInformation: ies.UPTransportLayerInformation{
           Choice: ies.UPTransportLayerInformationPresentGtptunnel,
           GTPTunnel: &ies.GTPTunnel{
               GTPTEID: dowlinkTeid,
               TransportLayerAddress: aper.BitString{
                   Bytes:   gnbIp,
                   NumBits: uint64(len(gnbIp) * 8),
               },
           },
       },
       AssociatedQosFlowList: []ies.AssociatedQosFlowItem{{QosFlowIdentifier: 1}},
   }


   var buf []byte
   var err error
   if buf, err = data.Encode(); err != nil {
       fmt.Printf("[gNB] Error encoding response transfer: %v\n", err)
       return nil
   }
   return buf
}


// sendPduSessionResourceSetupResponse - gửi response
func (gnb *GnbContext) sendPduSessionResourceSetupResponse(
   successList []ies.PDUSessionResourceSetupItemSURes,
   ranUeId, amfUeId int64,
) {
   fmt.Println("[gNB] Sending PDU Session Resource Setup Response")


   response := &ies.PDUSessionResourceSetupResponse{
       RANUENGAPID: ranUeId,
       AMFUENGAPID: amfUeId,
   }


   if len(successList) > 0 {
       response.PDUSessionResourceSetupListSURes = successList
       fmt.Printf("[gNB] Number of successful PDU Sessions: %d\n", len(successList))
   }


   buf, err := ngap.NgapEncode(response)
   if err != nil {
       fmt.Printf("[gNB] Failed to encode PDU Session Resource Setup Response: %v\n", err)
       return
   }


   if err := gnb.sctpConn.Send(buf); err != nil {
       fmt.Printf("[gNB] Failed to send PDU Session Resource Setup Response: %v\n", err)
       return
   }


   fmt.Println("[gNB] ========== Sent PDU Session Resource Setup Response → AMF ==========")
}


// handlerPduSessionReleaseCommand 
func (gnb *GnbContext) handlerPduSessionReleaseCommand(msg *ies.PDUSessionResourceReleaseCommand) {
   ranUeId := msg.RANUENGAPID
   amfUeId := msg.AMFUENGAPID
   messageNas := msg.NASPDU
   var pduSessionIds []int64


   if msg.PDUSessionResourceToReleaseListRelCmd == nil {
       fmt.Println("[gNB] ERROR: PDU SESSION RESOURCE TO RELEASE LIST is missing")
       return
   } else {
       for _, pDUSessionRessourceToReleaseItemRelCmd := range msg.PDUSessionResourceToReleaseListRelCmd {
           pduSessionIds = append(pduSessionIds, pDUSessionRessourceToReleaseItemRelCmd.PDUSessionID)
       }
   }


   for _, pduSessionId := range pduSessionIds {
       fmt.Printf("[gNB] Releasing PDU Session %d\n", pduSessionId)
   }


   // Forward NAS message to UE
   if len(messageNas) > 0 {
       fmt.Printf("[gNB] Forwarding NAS PDU (Release Command) to UE (%d bytes)\n", len(messageNas))
       select {
       case gnb.SendUeMsgChan <- messageNas:
           fmt.Println("[gNB] NAS PDU forwarded to UE")
       default:
           fmt.Println("[gNB] SendUeMsgChan full, cannot forward NAS PDU")
       }
   }


   gnb.sendPduSessionReleaseResponse(pduSessionIds, ranUeId, amfUeId)
}


func (gnb *GnbContext) sendPduSessionReleaseResponse(pduSessionIds []int64, ranUeId, amfUeId int64) {
   fmt.Println("[gNB] Sending PDU Session Resource Release Response")


   var releaseList []ies.PDUSessionResourceReleasedItemRelRes
   for _, pduSessionId := range pduSessionIds {
       item := ies.PDUSessionResourceReleasedItemRelRes{
           PDUSessionID: pduSessionId,
       }
       releaseList = append(releaseList, item)
   }


   response := &ies.PDUSessionResourceReleaseResponse{
       RANUENGAPID:                           ranUeId,
       AMFUENGAPID:                           amfUeId,
       PDUSessionResourceReleasedListRelRes: releaseList,
   }


   buf, err := ngap.NgapEncode(response)
   if err != nil {
       fmt.Printf("[gNB] Failed to encode PDU Session Resource Release Response: %v\n", err)
       return
   }


   if err := gnb.sctpConn.Send(buf); err != nil {
       fmt.Printf("[gNB] Failed to send PDU Session Resource Release Response: %v\n", err)
       return
   }


   fmt.Printf("[gNB] Successfully released %d PDU Session(s)\n", len(pduSessionIds))
   fmt.Println("[gNB] ========== Sent PDU Session Resource Release Response → AMF ==========")
}







