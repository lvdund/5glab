package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"emulator/internal/gnbcontext"
	"emulator/internal/sctp"
)

func main() {
	amfIp := flag.String("amf-ip", "192.168.56.101", "AMF IP")
	amfPort := flag.Int("amf-port", 38412, "AMF Port")
	gnbId := flag.String("gnb-id", "000009", "gNB ID")
	plmn := flag.String("plmn", "20893", "PLMN")
	tac := flag.Int("tac", 1, "TAC")
	flag.Parse()

	fmt.Println("========================================")
	fmt.Println("   TARGET gNB - Ready for Handover")
	fmt.Println("========================================")
	fmt.Printf("gNB ID: %s\n", *gnbId)
	fmt.Printf("AMF: %s:%d\n\n", *amfIp, *amfPort)

	ngMsgChan := make(chan []byte, 100)
	sendUeMsgChan := make(chan []byte, 100)
	revUeMsgChan := make(chan []byte, 100)

	sctpConn := sctp.NewSctpConn(*amfIp, *amfPort)
	if sctpConn == nil {
		log.Fatal("Failed to connect to AMF")
	}
	conn := sctpConn.GetConn()
	fmt.Println("SCTP connected")

	gnb := gnbcontext.NewGnbContext(
		*gnbId, *plmn, "192.168.1.3", *tac, 0,
		sctpConn, ngMsgChan, sendUeMsgChan, revUeMsgChan,
	)

	go gnb.HandleNgapMsg()
	go gnb.HandlerUeNasMsg()
	go gnb.HandleUeUplinkNAS()

	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				msg := make([]byte, n)
				copy(msg, buf[:n])
				ngMsgChan <- msg
			}
		}
	}()

	fmt.Println("Sending NG Setup Request...")
	if err := gnb.SendNgSetupRequest(); err != nil {
		log.Fatal(err)
	}

	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			log.Fatal("NG Setup timeout")
		case <-ticker.C:
			if gnb.AmfConnected {
				fmt.Println(" Target gNB connected to AMF")
				fmt.Println("\n========================================")
				fmt.Println("READY to receive handover")
				fmt.Println("Press Ctrl+C to stop")
				fmt.Println("========================================\n")
				goto READY
			}
		}
	}

READY:
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	conn.Close()
	fmt.Println("\nGoodbye.")
}
