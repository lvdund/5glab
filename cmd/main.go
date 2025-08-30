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

	ngMsgChan := make(chan []byte)
	revUeMsgChan := make(chan []byte)  // ue -> gnb
	sendUeMsgChan := make(chan []byte) // gnb -> ue

	// SCTP connect to AMF
	sctpConn := sctp.NewSctpConn(cfg.AMF.IP, cfg.AMF.Port)
	if sctpConn == nil {
		log.Fatalf("Failed to connect to AMF after 3 attempts")
	}
	conn := sctpConn.GetConn()

	// gNB context
	gnb := gnbcontext.NewGnbContext(
		cfg.GNB.GnbId, cfg.UE.PLMN, cfg.GNB.IP, int(cfg.GNB.TAC), cfg.GNB.Port,
		sctpConn,
		ngMsgChan, revUeMsgChan, sendUeMsgChan,
	)
	go gnb.HandleNgapMsg() // handle ngap msg from AMF

	// Send NGSetupRequest
	fmt.Printf("Sending NGSetupRequest with PLMN: %s, TAC: %06X\n", gnb.Plmn, gnb.Tac)
	if err = gnb.SendNgSetupRequest(conn); err != nil {
		log.Fatalf("NG Setup Request failed: %v", err)
	}
	fmt.Println("NG Setup Request sent to AMF")

	// check gnb connected to AMF
	time.Sleep(2 * time.Second)
	if !gnb.AmgConnected {
		log.Fatal("Cannot connect to AMF in 2 seconds")
	}

	// Init UE context
	ue := uecontext.NewUEContext(
		cfg.UE.SUPI,
		cfg.UE.PLMN,
		int(cfg.GNB.RanUeNgapIdStart),
		sendUeMsgChan,
		revUeMsgChan,
	)
	go ue.HandlerNasMsg() // handle nas msg from gnb

	_, _, err = ue.BuildRegistrationRequest()
	if err != nil {
		log.Fatalf("Err when encode nas registration request: %s", err.Error())
		return
	}

	// Wait for interrupt signal: Ctrl+C to exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	conn.Close()
}
