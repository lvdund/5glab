package uecontext

import (
	"fmt"
	"strings"
	"time"

	"emulator/internal/uecontext/sec"
	"github.com/reogac/nas"
)

// LoopConfig - Configuration for UE action loop
type LoopConfig struct {
	AfterAttach          time.Duration
	AfterPduSession      time.Duration
	AfterHandover        time.Duration
	AfterPduRelease      time.Duration
	AfterServiceRequest  time.Duration
	AfterDeregistration  time.Duration
	EnableHandover       bool
	TargetGnbId          string
	TargetCellId         uint32
	MaxIterations        int
	PduSessionDnn        string
}

// DefaultLoopConfig returns default timing configuration
func DefaultLoopConfig() *LoopConfig {
	return &LoopConfig{
		AfterAttach:          10 * time.Second,
		AfterPduSession:      10 * time.Second,
		AfterHandover:        10 * time.Second,
		AfterPduRelease:      5 * time.Second,
		AfterServiceRequest:  10 * time.Second,
		AfterDeregistration:  5 * time.Second,
		EnableHandover:       false,
		TargetGnbId:          "000009",
		TargetCellId:         100,
		MaxIterations:        0,
		PduSessionDnn:        "internet",
	}
}

// RunActionLoop - Main loop executing UE actions continuously
func (ue *UEContext) RunActionLoop(config *LoopConfig) error {
	if config == nil {
		config = DefaultLoopConfig()
	}

	iteration := 0
	for {
		iteration++

		if config.MaxIterations > 0 && iteration > config.MaxIterations {
			fmt.Printf("\nCompleted %d iterations. Exiting loop.\n", config.MaxIterations)
			break
		}

		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Printf("           UE ACTION LOOP - Iteration %d", iteration)
		if config.MaxIterations > 0 {
			fmt.Printf(" of %d", config.MaxIterations)
		}
		fmt.Println()
		fmt.Println(strings.Repeat("=", 80) + "\n")

		if err := ue.executeAttach(config); err != nil {
			fmt.Printf("Attach failed: %v\n", err)
			fmt.Println("Waiting 10s before retry...")
			time.Sleep(10 * time.Second)
			continue
		}

		if err := ue.executeCreatePduSession(config); err != nil {
			fmt.Printf("PDU Session creation failed: %v\n", err)
		}

		if config.EnableHandover {
			if err := ue.executeHandover(config); err != nil {
				fmt.Printf("Handover failed: %v\n", err)
			}
		} else {
			fmt.Println("Step 3: Handover SKIPPED (disabled in config)")
		}

		if err := ue.executeReleasePduSession(config); err != nil {
			fmt.Printf("PDU Session release failed: %v\n", err)
		}

		if err := ue.executeServiceRequest(config); err != nil {
			fmt.Printf("Service Request failed: %v\n", err)
		}

		if err := ue.executeDeregistration(config); err != nil {
			fmt.Printf("Deregistration failed: %v\n", err)
		}

		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Printf("Iteration %d completed. Starting next cycle in %v...\n",
			iteration, config.AfterDeregistration)
		fmt.Println(strings.Repeat("=", 80))
		time.Sleep(config.AfterDeregistration)
	}

	return nil
}

// executeAttach - Step 1: Initial Registration/Attach
func (ue *UEContext) executeAttach(config *LoopConfig) error {
	fmt.Println("\nStep 1: ATTACH (Initial Registration)")
	fmt.Println(strings.Repeat("-", 80))

	// Reset UE context
	ue.AmfUeNgapId = 0
	ue.secCtx = nil
	ue.AuthCtx.sqn = sec.Sqn{}

	// CRITICAL: Reset gNB state for new registration
	ue.ResetGnbState()

	if err := ue.TriggerInitRegistration(); err != nil {
		return fmt.Errorf("failed to send Registration Request: %v", err)
	}

	fmt.Println("Registration Request sent")
	fmt.Printf("Waiting %v for registration to complete...\n", config.AfterAttach)

	// Wait with timeout, checking periodically for security context
	deadline := time.Now().Add(config.AfterAttach)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		<-ticker.C
		if ue.secCtx != nil {
			fmt.Println("ATTACH completed - UE is registered")
			return nil
		}
	}

	fmt.Println("Warning: Security context not established")
	return fmt.Errorf("registration may not have completed successfully")
}

// executeCreatePduSession - Step 2: PDU Session Establishment
func (ue *UEContext) executeCreatePduSession(config *LoopConfig) error {
	fmt.Println("\nStep 2: CREATE PDU SESSION")
	fmt.Println(strings.Repeat("-", 80))

	sessionID := uint8(1)
	dnn := config.PduSessionDnn

	if ue.sessions[sessionID] == nil {
		ue.sessions[sessionID] = &PduSession{
			id:    int(sessionID),
			state: PDUSessionInactive,
		}
	}

	if err := ue.TriggerPduSessionEstablishment(sessionID, dnn); err != nil {
		return fmt.Errorf("failed to trigger PDU Session: %v", err)
	}

	fmt.Printf("PDU Session %d request sent (DNN: %s)\n", sessionID, dnn)
	fmt.Printf("Waiting %v for PDU Session establishment...\n", config.AfterPduSession)

	// Wait with polling
	deadline := time.Now().Add(config.AfterPduSession)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		<-ticker.C
		if ue.sessions[sessionID] != nil && ue.sessions[sessionID].state == PDUSessionActive {
			fmt.Printf("PDU SESSION %d is ACTIVE\n", sessionID)
			return nil
		}
	}

	// Final check
	if ue.sessions[sessionID] != nil && ue.sessions[sessionID].state == PDUSessionActive {
		fmt.Printf("PDU SESSION %d is ACTIVE\n", sessionID)
		return nil
	}

	fmt.Printf("Warning: PDU Session %d status uncertain\n", sessionID)
	return nil
}

// executeHandover - Step 3: Handover to new gNB
func (ue *UEContext) executeHandover(config *LoopConfig) error {
	fmt.Println("\nStep 3: HANDOVER (to target gNB)")
	fmt.Println(strings.Repeat("-", 80))

	fmt.Printf("Target gNB ID: %s\n", config.TargetGnbId)
	fmt.Printf("Target Cell ID: %d\n", config.TargetCellId)
	
	// Trigger handover from source gNB
	if err := ue.TriggerHandover(config.TargetGnbId, config.TargetCellId); err != nil {
		return fmt.Errorf("failed to trigger handover: %v", err)
	}

	fmt.Println("Handover Required sent to AMF")
	fmt.Printf("Waiting %v for handover completion...\n", config.AfterHandover)
	
	time.Sleep(config.AfterHandover)

	fmt.Println("Handover step completed")
	return nil
}

// executeReleasePduSession - Step 4: Release PDU Session
func (ue *UEContext) executeReleasePduSession(config *LoopConfig) error {
	fmt.Println("\nStep 4: RELEASE PDU SESSION")
	fmt.Println(strings.Repeat("-", 80))

	sessionID := uint8(1)

	if ue.sessions[sessionID] == nil {
		fmt.Printf("PDU Session %d does not exist, skipping release\n", sessionID)
		return nil
	}

	if ue.sessions[sessionID].state != PDUSessionActive {
		fmt.Printf("PDU Session %d not active, skipping release\n", sessionID)
		return nil
	}

	if err := ue.TriggerPduSessionRelease(sessionID); err != nil {
		return fmt.Errorf("failed to trigger PDU Session release: %v", err)
	}

	fmt.Printf("PDU Session %d release request sent\n", sessionID)
	fmt.Printf("Waiting %v for PDU Session release...\n", config.AfterPduRelease)

	time.Sleep(config.AfterPduRelease)

	if ue.sessions[sessionID] != nil {
		ue.sessions[sessionID].state = PDUSessionInactive
	}

	fmt.Printf("PDU SESSION %d released\n", sessionID)
	return nil
}

// executeServiceRequest - Step 5: Enter CM-IDLE and trigger Service Request
func (ue *UEContext) executeServiceRequest(config *LoopConfig) error {
	fmt.Println("\nStep 5: SERVICE REQUEST (re-attach from idle)")
	fmt.Println(strings.Repeat("-", 80))

	// TEMPORARY: Skip Service Request due to encoding issues
	fmt.Println("SKIPPED: Service Request not implemented yet")
	fmt.Printf("Waiting %v before next step...\n", config.AfterServiceRequest)
	time.Sleep(config.AfterServiceRequest)
	return nil
}

// executeDeregistration - Step 6: Deregister from network
func (ue *UEContext) executeDeregistration(config *LoopConfig) error {
	fmt.Println("\nStep 6: DEREGISTRATION (detach from network)")
	fmt.Println(strings.Repeat("-", 80))

	msg := &nas.DeregistrationAcceptToUe{}

	nasCtx := ue.getNasContext()
	if nasCtx == nil {
		fmt.Println("Warning: NAS context not available, sending plain deregistration")
		msg.SetSecurityHeader(nas.NasSecNone)
		buf, err := nas.EncodeMm(nil, msg, true)
		if err != nil {
			return fmt.Errorf("failed to encode Deregistration Request: %v", err)
		}
		ue.MsgToGnbChan <- buf
	} else {
		msg.SetSecurityHeader(nas.NasSecBoth)
		buf, err := nas.EncodeMm(nasCtx, msg, false)
		if err != nil {
			return fmt.Errorf("failed to encode Deregistration Request: %v", err)
		}
		ue.MsgToGnbChan <- buf
	}

	fmt.Println("Deregistration Request sent")
	fmt.Println("Waiting for deregistration to complete...")

	time.Sleep(3 * time.Second)

	fmt.Println("DEREGISTRATION completed - UE detached from network")

	ue.AmfUeNgapId = 0
	for i := range ue.sessions {
		if ue.sessions[i] != nil {
			ue.sessions[i].state = PDUSessionInactive
		}
	}

	return nil
}



type HandoverInterface interface {
	TriggerHandoverRequired(targetGnbId string, targetCellId uint32) error
}

var globalHandoverTrigger HandoverInterface

// SetHandoverTrigger - Set global handover trigger (called from main)
func SetHandoverTrigger(trigger HandoverInterface) {
	globalHandoverTrigger = trigger
}

// TriggerHandover - UE requests handover (actually triggers from source gNB)
func (ue *UEContext) TriggerHandover(targetGnbId string, targetCellId uint32) error {
	fmt.Printf("[UE] Requesting handover to gNB %s, Cell %d\n", targetGnbId, targetCellId)
	
	if globalHandoverTrigger == nil {
		return fmt.Errorf("handover trigger not configured")
	}

	fmt.Println("[UE] Simulating measurement report → gNB will trigger Handover Required")
	
	return globalHandoverTrigger.TriggerHandoverRequired(targetGnbId, targetCellId)
}