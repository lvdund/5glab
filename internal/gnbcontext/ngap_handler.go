package gnbcontext

import (
	"fmt"
	"log"

	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
)

// helper: normalize NASPDU to []byte
func nasToBytes(v interface{}) []byte {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case []byte:
		return t
	case aper.BitString:
		return t.Bytes
	case *aper.BitString:
		if t == nil {
			return nil
		}
		return t.Bytes
	default:
		return nil
	}
}

// ngapHandler: decode NGAP message và forward NAS → UE
func (gnb *GnbContext) ngapHandler(ngapPdu []byte, ueChan chan []byte, nasBuf chan []byte) {
	if len(ngapPdu) == 0 {
		log.Println("[gNB] NGAP message empty")
		return
	}

	ngapMsg, err, _ := ngap.NgapDecode(ngapPdu)
	if err != nil {
		log.Printf("[gNB] Error decoding NGAP: %v", err)
		return
	}

	switch ngapMsg.Present {
	case ies.NgapPduInitiatingMessage:
		switch ngapMsg.Message.ProcedureCode.Value {
		case ies.ProcedureCode_DownlinkNASTransport:
			fmt.Println("[gNB] Receive Downlink NAS Transport")
			if inner, ok := ngapMsg.Message.Msg.(*ies.DownlinkNASTransport); ok {
				// set IDs
				if inner.AMFUENGAPID != 0 {
					gnb.AmfUeNgapId = uint64(inner.AMFUENGAPID)
					fmt.Printf("[gNB] Set AMF_UE_NGAP_ID=%d\n", gnb.AmfUeNgapId)
				}
				if inner.RANUENGAPID != 0 {
					gnb.RanUeNgapId = uint64(inner.RANUENGAPID)
					fmt.Printf("[gNB] Set RAN_UE_NGAP_ID=%d\n", gnb.RanUeNgapId)
				}

				// UE context ready 
				gnb.ueContextReady = true

				// normalize NAS PDU → forward UE
				nas := nasToBytes(inner.NASPDU)
				if len(nas) > 0 {
					fmt.Printf("[gNB] Forward NAS → UE: %x\n", nas)
					select {
					case ueChan <- nas:
					default:
						log.Println("[gNB] ueChan full, drop NAS")
					}
				}
			}

		case ies.ProcedureCode_InitialContextSetup:
			fmt.Println("[gNB] Receive InitialContextSetupRequest")
			if inner, ok := ngapMsg.Message.Msg.(*ies.InitialContextSetupRequest); ok {
				if inner.AMFUENGAPID != 0 {
					gnb.AmfUeNgapId = uint64(inner.AMFUENGAPID)
				}
				if inner.RANUENGAPID != 0 {
					gnb.RanUeNgapId = uint64(inner.RANUENGAPID)
				}

				gnb.ueContextReady = true

				nas := nasToBytes(inner.NASPDU)
				if len(nas) > 0 {
					fmt.Printf("[gNB] Forward NAS (ICS) → UE: %x\n", nas)
					select {
					case ueChan <- nas:
					default:
						log.Println("[gNB] ueChan full, drop NAS in ICS")
					}
				}
			}

		case ies.ProcedureCode_ErrorIndication:
			if inner, ok := ngapMsg.Message.Msg.(*ies.ErrorIndication); ok {
				fmt.Printf("[gNB] ErrorIndication from AMF: AMFUENGAPID=%v, RANUENGAPID=%v, Cause=%v\n",
					inner.AMFUENGAPID, inner.RANUENGAPID, inner.Cause)
			}

		default:
			// ignore other initiating messages
		}

	case ies.NgapPduSuccessfulOutcome:
		if ngapMsg.Message.ProcedureCode.Value == ies.ProcedureCode_NGSetup {
			fmt.Println("[gNB] Receive NG Setup Response")
			gnb.AmfConnected = true
		}

	case ies.NgapPduUnsuccessfulOutcome:
		if ngapMsg.Message.ProcedureCode.Value == ies.ProcedureCode_NGSetup {
			fmt.Println("[gNB] Receive NG Setup Failure")
			gnb.AmfConnected = false
		}

	default:
		// unknown present
	}
}

// buildUplinkNasTransport: construct UplinkNASTransport safely
func (gnb *GnbContext) buildUplinkNasTransport(nasPdu []byte) ([]byte, error) {
	if !gnb.ueContextReady || gnb.AmfUeNgapId == 0 || gnb.RanUeNgapId == 0 {
		return nil, fmt.Errorf("Cannot encode: ueContextReady=%v AMF=%d RAN=%d",
			gnb.ueContextReady, gnb.AmfUeNgapId, gnb.RanUeNgapId)
	}

	msg := ies.UplinkNASTransport{
		AMFUENGAPID: int64(gnb.AmfUeNgapId),
		RANUENGAPID: int64(gnb.RanUeNgapId),
		NASPDU:      nasPdu,
	}

	// UserLocationInformation NR (Choice ≥ 2)
	msg.UserLocationInformation = ies.UserLocationInformation{
		Choice: 2,
		UserLocationInformationNR: &ies.UserLocationInformationNR{
			NRCGI: ies.NRCGI{
				PLMNIdentity:   gnb.getMccAndMncInOctets(),
				NRCellIdentity: aper.BitString{Bytes: gnb.GetNRCellIdentity(), NumBits: 36},
			},
			TAI: ies.TAI{
				PLMNIdentity: gnb.getMccAndMncInOctets(),
				TAC:          gnb.getTacInBytes(),
			},
		},
	}

	return ngap.NgapEncode(&msg)
}

// sendUplinkNAS: wrapper to send NAS
func (gnb *GnbContext) sendUplinkNAS(nasPdu []byte) {
	nasBytes := nasToBytes(nasPdu)
	if len(nasBytes) == 0 {
		log.Println("[gNB] NAS PDU empty, skip send")
		return
	}

	buf, err := gnb.buildUplinkNasTransport(nasBytes)
	if err != nil {
		log.Printf("[gNB] Cannot build UplinkNASTransport: %v", err)
		// buffer to retry
		select {
		case gnb.nasBuf <- nasBytes:
		default:
			select {
			case <-gnb.nasBuf:
			default:
			}
			gnb.nasBuf <- nasBytes
		}
		return
	}

	if err := gnb.sctpConn.Send(buf); err != nil {
		log.Printf("[gNB] Failed to send UplinkNASTransport: %v", err)
		// buffer to retry
		select {
		case gnb.nasBuf <- nasBytes:
		default:
			select {
			case <-gnb.nasBuf:
			default:
			}
			gnb.nasBuf <- nasBytes
		}
		return
	}

	fmt.Println("[gNB] Sent UplinkNASTransport → AMF (PPID=60)")
}
