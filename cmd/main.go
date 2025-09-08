package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"emulator/internal/gnbcontext"
	"emulator/internal/sctp"
	"emulator/internal/uecontext"
	"emulator/pkg/config"
)

func main() {
	// Load config
	cfg, err := config.Load("config.yaml")
	if err != nil {
		panic(err)
	}

	// Channels for UE <-> gNB communication
	ngMsgChan := make(chan []byte)      // NGAP messages from gNB
	sendUeMsgChan := make(chan []byte)  // UE -> gNB
	revUeMsgChan := make(chan []byte)   // gNB -> UE

	// SCTP connect to AMF
	sctpConn := sctp.NewSctpConn(cfg.AMF.IP, cfg.AMF.Port)
	if sctpConn == nil {
		log.Fatalf("Failed to connect to AMF")
	}
	conn := sctpConn.GetConn()

	// Create gNB context
	gnb := gnbcontext.NewGnbContext(
		cfg.GNB.GnbId, cfg.UE.PLMN, cfg.GNB.IP, int(cfg.GNB.TAC), cfg.GNB.Port,
		sctpConn,
		ngMsgChan, revUeMsgChan, sendUeMsgChan,
	)

	// Start NGAP handler
	go gnb.HandleNgapMsg()

	// Goroutine: forward UE NAS messages to gNB
	/*go func() {
		for msg := range sendUeMsgChan {
			gnb.RevUeMsgChan <- msg
		}
	}()*/

/*	// Goroutine: gNB forward NAS message to AMF via SCTP
go func() {
    for msg := range gnb.RevUeMsgChan {
        fmt.Println("[gNB] Sending NAS msg to AMF, len:", len(msg))
        err = sctpConn.Send(msg) // gửi NAS message qua SCTP
        if err != nil {
            fmt.Println("[gNB] Error sending NAS to AMF:", err)
        }
    }
}()
*/
go gnb.HandlerUeNasMsg()

// Forward NAS từ UEContext sang gNB UeUplinkChan
go func() {
    for msg := range sendUeMsgChan {  // sendUeMsgChan: UE -> gNB
        gnb.UeUplinkChan <- msg       // gửi vào channel mới
    }
}()

// Goroutine: gNB process NAS from UE → UplinkNASTransport
go gnb.HandleUeUplinkNAS()


	// Goroutine: read NGAP from AMF
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			fmt.Println("[gNB] SCTP Write returned:", n, err)
			if err != nil {
				log.Printf("Error reading from AMF: %v", err)
				close(gnb.NgapMsgChan)
				return
			}
			msg := make([]byte, n)
			copy(msg, buf[:n])
			log.Printf("Received raw NGAP msg: %x", msg)
			gnb.NgapMsgChan <- msg
		}
	}()

	// Send NGSetupRequest
	fmt.Printf("Sending NGSetupRequest with PLMN: %s, TAC: %06X\n", gnb.Plmn, gnb.Tac)
	if err := gnb.SendNgSetupRequest(); err != nil {
		log.Fatalf("NG Setup Request failed: %v", err)
	}

	// Wait for NGSetupResponse (timeout 15s)
	timeout := time.After(15* time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

waitAMF:
	for {
		select {
		case <-timeout:
			log.Fatal("Timeout: did not receive NGSetupResponse from AMF")
		case <-ticker.C:
			if gnb.AmfConnected {
				fmt.Println("gNB successfully connected to AMF")
				break waitAMF
			}
		}
	}

	// Initialize UE context
	ue := uecontext.NewUEContext(
		cfg.UE.SUPI,
		cfg.UE.PLMN,
		int(cfg.GNB.RanUeNgapIdStart),
		sendUeMsgChan,   // UE -> gNB
		revUeMsgChan,    // gNB -> UE
	)

	// Start UE NAS handler
	go ue.HandlerNasMsg()

	// Build and send NAS Registration Request
	if err := ue.TriggerInitRegistration(); err != nil {
		log.Fatalf("Failed to send Registration Request: %v", err)
	}
	fmt.Println("NAS RegistrationRequest sent")

	// Wait for Ctrl+C to exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("Exiting...")
	conn.Close()
}
