package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"emulator/internal/gnbcontext"
	"emulator/internal/sctp"
	"emulator/internal/uecontext"
	"emulator/pkg/config"
)

func main() {
	configFile := flag.String("config", "config.yaml", "Config file path")
	maxIterations := flag.Int("iterations", 0, "Max iterations (0=infinite)")
	afterAttach := flag.Int("after-attach", 10, "Wait time after attach (seconds)")
	afterPdu := flag.Int("after-pdu", 10, "Wait time after PDU session (seconds)")
	afterRelease := flag.Int("after-release", 5, "Wait time after PDU release (seconds)")
	afterService := flag.Int("after-service", 10, "Wait time after service request (seconds)")
	afterDereg := flag.Int("after-dereg", 5, "Wait time after deregistration (seconds)")
	enableHandover := flag.Bool("enable-handover", false, "Enable handover step")
	targetGnbId := flag.String("target-gnb", "000009", "Target gNB ID for handover")
	targetCellId := flag.Uint("target-cell", 100, "Target Cell ID for handover")
	flag.Parse()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("           UE ACTION LOOP SIMULATOR - COMPLETE VERSION")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("Configuration:\n")
	fmt.Printf("  AMF: %s:%d\n", cfg.AMF.IP, cfg.AMF.Port)
	fmt.Printf("  gNB ID: %s\n", cfg.GNB.GnbId)
	fmt.Printf("  PLMN: %s\n", cfg.UE.PLMN)
	fmt.Printf("  SUPI: %s\n", cfg.UE.SUPI)
	fmt.Printf("\nLoop Configuration:\n")
	fmt.Printf("  Max Iterations: %d", *maxIterations)
	if *maxIterations == 0 {
		fmt.Printf(" (infinite)")
	}
	fmt.Printf("\n")
	fmt.Printf("  After Attach: %ds\n", *afterAttach)
	fmt.Printf("  After PDU Session: %ds\n", *afterPdu)
	fmt.Printf("  After Release: %ds\n", *afterRelease)
	fmt.Printf("  After Service Request: %ds\n", *afterService)
	fmt.Printf("  After Deregistration: %ds\n", *afterDereg)
	fmt.Printf("  Handover Enabled: %v\n", *enableHandover)
	if *enableHandover {
		fmt.Printf("  Target gNB ID: %s\n", *targetGnbId)
		fmt.Printf("  Target Cell ID: %d\n", *targetCellId)
	}
	fmt.Println()

	// Setup channels
	ngMsgChan := make(chan []byte, 100)
	sendUeMsgChan := make(chan []byte, 100)
	revUeMsgChan := make(chan []byte, 100)

	fmt.Println("[DEBUG] Channels created:")
	fmt.Printf("  ngMsgChan: %p (cap=%d)\n", ngMsgChan, cap(ngMsgChan))
	fmt.Printf("  sendUeMsgChan: %p (cap=%d)\n", sendUeMsgChan, cap(sendUeMsgChan))
	fmt.Printf("  revUeMsgChan: %p (cap=%d)\n", revUeMsgChan, cap(revUeMsgChan))

	// Connect to AMF
	fmt.Printf("\nConnecting to AMF at %s:%d...\n", cfg.AMF.IP, cfg.AMF.Port)
	sctpConn := sctp.NewSctpConn(cfg.AMF.IP, cfg.AMF.Port)
	if sctpConn == nil {
		log.Fatal("Failed to connect to AMF")
	}
	conn := sctpConn.GetConn()
	fmt.Println("SCTP connection established")

	// Create gNB context
	gnb := gnbcontext.NewGnbContext(
		cfg.GNB.GnbId,
		cfg.UE.PLMN,
		cfg.GNB.IP,
		int(cfg.GNB.TAC),
		cfg.GNB.Port,
		sctpConn,
		ngMsgChan,
		sendUeMsgChan,
		revUeMsgChan,
	)

	// Start gNB handlers
	fmt.Println("\n[DEBUG] Starting gNB handlers...")
	go gnb.HandleNgapMsg()
	go gnb.HandlerUeNasMsg()
	go gnb.HandleUeUplinkNAS()
	fmt.Println("[DEBUG] All gNB handlers started")

	// Monitor channels
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("[MONITOR] Channels: ngMsg=%d, sendUe=%d, revUe=%d\n",
				len(ngMsgChan), len(sendUeMsgChan), len(revUeMsgChan))
		}
	}()

	// Read NGAP from AMF
	go func() {
		buf := make([]byte, 8192)
		fmt.Println("[DEBUG] Started NGAP reader goroutine")
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("[ERROR] Error reading from AMF: %v", err)
				close(ngMsgChan)
				return
			}
			if n > 0 {
				fmt.Printf("[DEBUG] Read %d bytes from AMF\n", n)
				msg := make([]byte, n)
				copy(msg, buf[:n])
				ngMsgChan <- msg
				fmt.Printf("[DEBUG] Forwarded to ngMsgChan (len=%d)\n", len(ngMsgChan))
			}
		}
	}()

	// Send NG Setup Request
	fmt.Println("\nSending NG Setup Request...")
	if err := gnb.SendNgSetupRequest(); err != nil {
		log.Fatalf("NG Setup Request failed: %v", err)
	}

	// Wait for NG Setup Response
	fmt.Print("Waiting for NG Setup Response")
	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

waitAMF:
	for {
		select {
		case <-timeout:
			fmt.Println(" - Timeout")
			log.Fatal("Timeout: did not receive NG Setup Response")
		case <-ticker.C:
			fmt.Print(".")
			if gnb.AmfConnected {
				fmt.Println(" OK")
				fmt.Println("gNB connected to AMF")
				break waitAMF
			}
		}
	}

	// Create UE context
	ranUeNgapId := int64(cfg.GNB.RanUeNgapIdStart)
	fmt.Printf("\n[DEBUG] Creating UE context with RAN UE NGAP ID: %d\n", ranUeNgapId)
	ue := uecontext.NewUEContext(
		cfg.UE.SUPI,
		cfg.UE.PLMN,
		int(ranUeNgapId),
		revUeMsgChan,
		sendUeMsgChan,
	)

	// Start UE NAS handler
	fmt.Println("[DEBUG] Starting UE NAS handler...")
	go ue.HandlerNasMsg()
	fmt.Println("[DEBUG] UE NAS handler started")

	// CRITICAL: Connect UE with gNB for state reset and handover
	uecontext.SetGnbResetter(gnb)
	uecontext.SetHandoverTrigger(gnb)
	fmt.Println("[DEBUG] UE connected to gNB (resetter + handover trigger)")

	// Monitor UE channels
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("[UE-MONITOR] revUeMsgChan len=%d, sendUeMsgChan len=%d\n",
				len(revUeMsgChan), len(sendUeMsgChan))
		}
	}()

	// Setup loop configuration
	loopCfg := &uecontext.LoopConfig{
		AfterAttach:         time.Duration(*afterAttach) * time.Second,
		AfterPduSession:     time.Duration(*afterPdu) * time.Second,
		AfterHandover:       10 * time.Second,
		AfterPduRelease:     time.Duration(*afterRelease) * time.Second,
		AfterServiceRequest: time.Duration(*afterService) * time.Second,
		AfterDeregistration: time.Duration(*afterDereg) * time.Second,
		EnableHandover:      *enableHandover,
		TargetGnbId:         *targetGnbId,
		TargetCellId:        uint32(*targetCellId),
		MaxIterations:       *maxIterations,
		PduSessionDnn:       "internet",
	}

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Run loop in goroutine
	loopDone := make(chan error, 1)
	go func() {
		fmt.Println("[DEBUG] Starting action loop...")
		loopDone <- ue.RunActionLoop(loopCfg)
	}()

	// Wait for loop to complete or signal
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("Press Ctrl+C to stop the loop")
	fmt.Println(strings.Repeat("=", 80) + "\n")

	select {
	case err := <-loopDone:
		if err != nil {
			log.Printf("Loop ended with error: %v", err)
		} else {
			fmt.Println("\nLoop completed successfully")
		}
	case sig := <-sigChan:
		fmt.Printf("\nReceived signal: %v\n", sig)
		fmt.Println("Shutting down gracefully...")
	}

	// Cleanup
	conn.Close()
	fmt.Println("Goodbye.")
}