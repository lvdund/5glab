package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Phuc12012005/emulator/internal/gnb"
	"github.com/Phuc12012005/emulator/internal/sctpngap"
	"github.com/Phuc12012005/emulator/internal/ue"
	"github.com/Phuc12012005/emulator/pkg/config"
	"github.com/ishidawataru/sctp"
)

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalln("Error in loading config file ", err)
	}
	amfAddr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.ParseIP(cfg.AMF.IP)}},
		Port:    38412,
	}

	conn, err := sctp.DialSCTP("sctp", nil, amfAddr)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	go sctpngap.SctpListen(conn) // keep connection to amf
	fmt.Println("Gnb established connection to the AMF")

	gnb := gnb.NewGNodeB(cfg.GNB.GNBID, cfg.GNB.TAC, cfg.GNB.Port, cfg.UE.PLMN, cfg.GNB.IP)

	msg := gnb.GetNgSetupRequest() // create NG Setup Request
	if msg == nil {
		log.Fatalf("Failed to encode")
		return
	}
	sctpngap.SctpWrite(msg, conn) // send ngap msg to AMF

	ue := ue.NewUserEquipment(cfg.UE.SUPI, cfg.UE.PLMN, cfg.GNB.RanUeNgapStart)
	_, nasBuf, err := ue.BuildRegistrantionUeMsg()
	go ue.HandleNasPdu(nasBuf)
	// Wait for interrupt signal: Ctrl+C to exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	conn.Close()

}
