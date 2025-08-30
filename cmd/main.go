package main

import (
	"fmt"
	"log"
	"time"

	"emulator/internal/sctp"
	"emulator/internal/uecontext"
	"emulator/internal/ngap"
	"emulator/pkg/config"
	"emulator/internal/gnbcontext"

	inas "emulator/internal/nas"
	rnas "github.com/reogac/nas"

	gosctp "github.com/ishidawataru/sctp"
	"github.com/lvdund/ngap/ies"
)

func main() {
	// Load config
	cfg, err := config.Load("config.yaml")
	if err != nil {
		panic(err)
	}

	// Init UE context
	ue := uecontext.NewUEContext(cfg.UE.SUPI, cfg.UE.PLMN, int(cfg.GNB.RanUeNgapIdStart))
	ue.Snssai = []byte{0x01, 0x01, 0x02, 0x03}
	fmt.Println("UE Context:", ue)

	// SCTP connect to AMF
	var conn *gosctp.SCTPConn
	for i := 0; i < 3; i++ {
		conn, err = sctp.ConnectToAmf(cfg.AMF.IP, cfg.AMF.Port)
		if err != nil {
			fmt.Printf("Attempt %d: SCTP connection failed: %v\n", i+1, err)
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}
	if conn == nil {
		log.Fatalf("Failed to connect to AMF after 3 attempts")
	}
	defer conn.Close()
	fmt.Println("Connected to AMF.")

	// gNB context
	gnb := &gnbcontext.GnbContext{
		GnbId: cfg.GNB.GnbId,
		Plmn:  cfg.UE.PLMN,
		Tac:   uint32(cfg.GNB.TAC),
		Ip:    cfg.GNB.IP,
		Port:  cfg.GNB.Port,
	}

	// Send NGSetupRequest
	fmt.Printf("Sending NGSetupRequest with PLMN: %s, TAC: %06X\n", gnb.Plmn, gnb.Tac)
	if err = gnb.SendNgSetupRequest(conn); err != nil {
		log.Fatalf("NG Setup Request failed: %v", err)
	}
	fmt.Println("NG Setup Request sent to AMF")

	// Prepare NAS context
	ueNas := &inas.UEContext{
		SUPI:   ue.SUPI,
		PLMN:   ue.PLMN,
		Snssai: ue.Snssai,
	}
	nasCtx := rnas.NewNasContext(false)

	// Wait for response
	done := make(chan bool)
	go func() {
		defer close(done)
		fmt.Println("Waiting for NGAP messages from AMF...")

		recvBuf := make([]byte, 4096)
		n, err := conn.Read(recvBuf)
		if err != nil {
			log.Fatalf("Failed to read NGAP: %v", err)
			return
		}

		_, err, msg := ngap.DecodeMessage(recvBuf[:n])
		if err != nil {
			log.Fatalf("NGAP decode failed: %v", err)
			return
		}

		fmt.Println("Received NGAP message from AMF.")
		fmt.Printf("Received raw bytes (%d bytes): % X\n", n, recvBuf[:n])

		switch m := msg.(type) {
		case *ies.NGSetupResponse:
			fmt.Println("NGSetupResponse received from AMF")
			fmt.Printf("NGSetupResponse struct: %+v\n", m)

			// send InitialUEMessage (RegistrationRequest)
			_, nasBuf, err := inas.BuildRegistrationRequest(ueNas)
			if err != nil {
				log.Fatalf("NAS build failed: %v", err)
			}
			fmt.Printf("NAS RegistrationRequest: PLMN=%s, TAC=%06X, S-NSSAI=% X\n",
				ueNas.PLMN, gnb.Tac, ueNas.Snssai)

			ngapMsg := ngap.InitialUEMessage{
				NASPdu: nasBuf,
			}
			ngapBuf, err := ngap.EncodeMessage(ngapMsg)
			if err != nil {
				log.Fatalf("NGAP encode failed: %v", err)
			}

			info := &gosctp.SndRcvInfo{Stream: 0, PPID: 60}
			if _, err = conn.SCTPWrite(ngapBuf, info); err != nil {
				log.Fatalf("Failed to send InitialUEMessage: %v", err)
			}
			fmt.Println("Sent InitialUEMessage → AMF (PPID=60)")

		case *ies.DownlinkNASTransport:
			fmt.Println("DownlinkNASTransport received from AMF")
			fmt.Printf("NAS-PDU raw: % X\n", m.NASPDU)
			if len(m.NASPDU) > 0 {
				inas.HandleNasPdu(m.NASPDU, nasCtx)
			}

		default:
			fmt.Printf("Unhandled NGAP message type: %T\n", m)
		}
	}()

	select {
	case <-done:
		fmt.Println("Response processing finished.")
	case <-time.After(30 * time.Second):
		fmt.Println("Timeout: Did not receive response from AMF within 30s")
	}

	fmt.Println("Program finished.")
}
