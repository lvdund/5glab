package gnbcontext

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
)

// TriggerHandoverRequired 
func (gnb *GnbContext) TriggerHandoverRequired(targetGnbId string, targetCellId uint32) error {
	// Validation
	if gnb.AmfUeNgapId == 0 || gnb.RanUeNgapId == 0 {
		return fmt.Errorf("UE context not ready (AMF_ID=%d, RAN_ID=%d)", 
			gnb.AmfUeNgapId, gnb.RanUeNgapId)
	}

	if !gnb.ueContextReady {
		return fmt.Errorf("UE context not ready yet")
	}

	fmt.Printf("\n[Source gNB] ========== Triggering Handover ==========\n")
	fmt.Printf("[Source gNB] Source gNB ID: %s\n", gnb.GnbId)
	fmt.Printf("[Source gNB] Source RAN UE NGAP ID: %d\n", gnb.RanUeNgapId)
	fmt.Printf("[Source gNB] AMF UE NGAP ID: %d\n", gnb.AmfUeNgapId)
	fmt.Printf("[Source gNB] Target gNB ID: %s\n", targetGnbId)
	fmt.Printf("[Source gNB] Target Cell ID: %d\n", targetCellId)

	// Parse target gNB ID (hex string like "000009")
	var targetBytes [3]byte
	if len(targetGnbId) == 6 {
		_, err := fmt.Sscanf(targetGnbId, "%02x%02x%02x", 
			&targetBytes[0], &targetBytes[1], &targetBytes[2])
		if err != nil {
			return fmt.Errorf("failed to parse target gNB ID: %v", err)
		}
	} else {
		return fmt.Errorf("invalid target gNB ID format: %s (expected 6 hex chars)", targetGnbId)
	}

	plmn := gnb.getMccAndMncInOctets()

	targetGlobalRANNodeID := ies.GlobalRANNodeID{
		Choice: 1, // GlobalGNBID present
		GlobalGNBID: &ies.GlobalGNBID{
			PLMNIdentity: plmn,
			GNBID: ies.GNBID{
				Choice: 1, // GNBID present (not GNB-ID)
				GNBID: &aper.BitString{
					Bytes:   targetBytes[:],
					NumBits: 24,
				},
			},
		},
	}

	targetID := ies.TargetID{
		Choice: 1, // TargetRANNodeID present
		TargetRANNodeID: &ies.TargetRANNodeID{
			GlobalRANNodeID: targetGlobalRANNodeID,
			SelectedTAI: ies.TAI{
				PLMNIdentity: plmn,
				TAC:          gnb.getTacInBytes(),
			},
		},
	}

	// Build minimal but valid transparent container
	sourceToTargetContainer := []byte{
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	// Build PDU Session list
	pduSessionList := []ies.PDUSessionResourceItemHORqd{
		{
			PDUSessionID: 1,
			HandoverRequiredTransfer: []byte{0x00, 0x01, 0x00},
		},
	}

	msg := &ies.HandoverRequired{
		RANUENGAPID:  int64(gnb.RanUeNgapId),
		AMFUENGAPID:  int64(gnb.AmfUeNgapId),

		HandoverType: ies.HandoverType{Value: 0},

		Cause: ies.Cause{
			Choice: 1, // RadioNetwork
			RadioNetwork: &ies.CauseRadioNetwork{
				Value: 1, 
			},
		},

		TargetID: targetID,

		PDUSessionResourceListHORqd: pduSessionList,

		SourceToTargetTransparentContainer: sourceToTargetContainer,
	}

	// Encode
	buf, err := ngap.NgapEncode(msg)
	if err != nil {
		return fmt.Errorf("encode failed: %v", err)
	}

	fmt.Printf("[DEBUG] Encoded NGAP message (%d bytes)\n", len(buf))
	fmt.Printf("[DEBUG] Hex (first 100 bytes): %s\n", 
		hex.EncodeToString(buf[:min(100, len(buf))]))

	// Send to AMF
	if err := gnb.sctpConn.Send(buf); err != nil {
		return fmt.Errorf("send failed: %v", err)
	}

	fmt.Println("[Source gNB] ========== Sent Handover Required → AMF ==========")
	fmt.Println("[Source gNB]  Waiting for Handover Command...")

	return nil
}

// handlerHandoverRequest - Target gNB receives this
func (gnb *GnbContext) handlerHandoverRequest(msg *ies.HandoverRequest) {
	fmt.Printf("\n[Target gNB] ========== Received Handover Request ==========\n")
	fmt.Printf("[Target gNB] AMF UE NGAP ID: %d\n", msg.AMFUENGAPID)
	
	// Allocate new RAN UE NGAP ID for target gNB
	newRanUeId := gnb.RanUeNgapId
	gnb.RanUeNgapId++
	gnb.AmfUeNgapId = uint64(msg.AMFUENGAPID)
	gnb.ueContextReady = true

	fmt.Printf("[Target gNB] Allocated new RAN UE NGAP ID: %d\n", newRanUeId)

	// Process PDU Sessions
	if msg.PDUSessionResourceSetupListHOReq != nil {
		for _, item := range msg.PDUSessionResourceSetupListHOReq {
			fmt.Printf("[Target gNB] PDU Session %d will be transferred\n", item.PDUSessionID)
		}
	}

	// Send Handover Request Acknowledge
	gnb.sendHandoverRequestAcknowledge(newRanUeId, msg.AMFUENGAPID)

	// Auto send Handover Notify after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		gnb.sendHandoverNotify()
	}()
}

// sendHandoverRequestAcknowledge 
func (gnb *GnbContext) sendHandoverRequestAcknowledge(ranUeId uint64, amfUeId int64) {
	fmt.Println("\n[Target gNB] Preparing Handover Request Acknowledge...")

	rrcContainer := []byte{
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	admittedList := []ies.PDUSessionResourceAdmittedItem{
		{
			PDUSessionID: 1,
			HandoverRequestAcknowledgeTransfer: []byte{0x00, 0x01, 0x00},
		},
	}

	response := &ies.HandoverRequestAcknowledge{
		RANUENGAPID:                         int64(ranUeId),
		AMFUENGAPID:                         amfUeId,
		PDUSessionResourceAdmittedList:      admittedList,
		TargetToSourceTransparentContainer:  rrcContainer,
	}

	buf, err := ngap.NgapEncode(response)
	if err != nil {
		log.Printf("[Target gNB] Encode error: %v", err)
		return
	}

	if err := gnb.sctpConn.Send(buf); err != nil {
		log.Printf("[Target gNB] Send error: %v", err)
		return
	}

	fmt.Println("[Target gNB] ========== Sent Handover Request Acknowledge ==========")
}

// handlerHandoverCommand - Source gNB receives this
func (gnb *GnbContext) handlerHandoverCommand(msg *ies.HandoverCommand) {
	fmt.Printf("\n[Source gNB] ========== Received Handover Command ==========\n")
	fmt.Printf("[Source gNB] RAN UE NGAP ID: %d\n", msg.RANUENGAPID)
	fmt.Printf("[Source gNB] AMF UE NGAP ID: %d\n", msg.AMFUENGAPID)

	if msg.PDUSessionResourceHandoverList != nil {
		for _, item := range msg.PDUSessionResourceHandoverList {
			fmt.Printf("[Source gNB] PDU Session %d handover command received\n", 
				item.PDUSessionID)
		}
	}

	// Extract target-to-source transparent container
	if len(msg.TargetToSourceTransparentContainer) > 0 {
		fmt.Printf("[Source gNB] Received RRC Reconfiguration (%d bytes)\n", 
			len(msg.TargetToSourceTransparentContainer))
		
		fmt.Println("[Source gNB] Forwarding Handover Command to UE...")
		select {
		case gnb.SendUeMsgChan <- msg.TargetToSourceTransparentContainer:
			fmt.Println("[Source gNB] Handover Command forwarded to UE")
		default:
			fmt.Println("[Source gNB]  Failed to forward to UE (channel full)")
		}
	}

	fmt.Println("[Source gNB]  Handover Command received successfully ✓✓✓")
	fmt.Println("[Source gNB] Waiting for UE to complete handover at target...")
}

// sendHandoverNotify - Target gNB sends this after UE completes handover
func (gnb *GnbContext) sendHandoverNotify() {
	if gnb.AmfUeNgapId == 0 || gnb.RanUeNgapId == 0 {
		log.Println("[Target gNB] Cannot send Handover Notify: context not ready")
		return
	}

	fmt.Println("\n[Target gNB] Sending Handover Notify...")

	msg := &ies.HandoverNotify{
		RANUENGAPID: int64(gnb.RanUeNgapId),
		AMFUENGAPID: int64(gnb.AmfUeNgapId),
		UserLocationInformation: ies.UserLocationInformation{
			Choice: 1, // UserLocationInformationNR
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

	buf, err := ngap.NgapEncode(msg)
	if err != nil {
		log.Printf("[Target gNB] Encode error: %v", err)
		return
	}

	if err := gnb.sctpConn.Send(buf); err != nil {
		log.Printf("[Target gNB] Send error: %v", err)
		return
	}

	fmt.Println("[Target gNB] ========== Sent Handover Notify → AMF ==========")
	fmt.Println("[Target gNB] HANDOVER COMPLETED SUCCESSFULLY ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}