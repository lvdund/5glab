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
	"github.com/ishidawataru/sctp"
)

func main() {
	amfAddr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.ParseIP("192.168.56.3")}},
		Port:    38412,
	}

	conn, err := sctp.DialSCTP("sctp", nil, amfAddr)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	go sctpngap.SctpListen(conn) // keep connection to amf
	fmt.Println("Gnb established connection to the AMF")

	gnb := gnb.Gnb{}

	msg := gnb.GetNgSetupRequest() // create NG Setup Request
	if msg == nil {
		log.Fatalf("Failed to encode")
		return
	}
	sctpngap.SctpWrite(msg, conn) // send ngap msg to AMF

	// Wait for interrupt signal: Ctrl+C to exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	conn.Close()

}
