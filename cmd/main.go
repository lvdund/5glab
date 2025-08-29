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
)

func main() {
	// Load config
	cfg, err := config.Load("config.yaml")
	if err != nil {
		panic(err)
	}



	// Init UE context
	ue := uecontext.NewUEContext(cfg.UE.SUPI, cfg.UE.PLMN, int(cfg.GNB.RanUeNgapIdStart))
	// Add S-NSSAI
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

	fmt.Printf("Sending NGSetupRequest with PLMN: %s, TAC: %06X\n", gnb.Plmn, gnb.Tac)
	if err = gnb.SendNgSetupRequest(conn); err != nil {
		log.Fatalf("NG Setup Request failed: %v", err)
	}
	fmt.Println("NG Setup Request sent to AMF")


	// Convert uecontext.UEContext -> INTERNAL nas.UEContext
	ueNas := &inas.UEContext{
		SUPI:   ue.SUPI,
		PLMN:   ue.PLMN,
		Snssai: ue.Snssai,
	}



	// Build NAS Registration Request (use INTERNAL nas)
	_, nasBuf, err := inas.BuildRegistrationRequest(ueNas)
	if err != nil {
		log.Fatalf("NAS build failed: %v", err)
	}
	fmt.Printf("NAS RegistrationRequest: PLMN=%s, TAC=%06X, S-NSSAI=% X\n",
		ueNas.PLMN, gnb.Tac, ueNas.Snssai)




	// InitialUEMessage NGAP
	ngapMsg := ngap.InitialUEMessage{
		NASPdu: nasBuf,
	}
	ngapBuf, err := ngap.EncodeMessage(ngapMsg)
	if err != nil {
		log.Fatalf("NGAP encode failed: %v", err)
	}

	info := &gosctp.SndRcvInfo{
		Stream: 0,
		PPID:   60,
	}
	if _, err = conn.SCTPWrite(ngapBuf, info); err != nil {
		log.Fatalf("Failed to send NGAP Registration Request: %v", err)
	}
	fmt.Println("Sent Registration Request → AMF (PPID=60)")



	//  NAS context to decode/encode 
	nasCtx := rnas.NewNasContext(false)



	// wait for response
	done := make(chan bool)
	go func() {
		defer close(done)
		fmt.Println("Waiting for Registration Accept from AMF...")

		recvBuf := make([]byte, 4096)
		n, err := conn.Read(recvBuf)
		if err != nil {
			log.Fatalf("Failed to read NGAP: %v", err)
			return
		}

		pdu, err, msg := ngap.DecodeMessage(recvBuf[:n])
		if err != nil {
			log.Fatalf("NGAP decode failed: %v", err)
			return
		}
		fmt.Println("Received NGAP message from AMF.")
		fmt.Printf("Received raw bytes (%d bytes): % X\n", n, recvBuf[:n])
		fmt.Printf("ProcedureCode=%d\n", pdu.ProcedureCode)

		switch m := msg.(type) {
		case *ngap.DownlinkNASTransport:
    fmt.Println("DownlinkNASTransport received from AMF")
    if len(m.NASPdu) > 0 {
        nasPdu := m.NASPdu
        if len(nasPdu) >= 3 {
            l := int(nasPdu[1])<<8 | int(nasPdu[2])
            if len(nasPdu) >= 3+l {
                realNas := nasPdu[3 : 3+l]
                inas.HandleNasPdu(realNas, nasCtx)
            } else {
                fmt.Println("NAS-PDU length mismatch")
            }
        } else {
            fmt.Println("Invalid NAS-PDU IE")
        }
    }
		case *ngap.InitialContextSetupRequest:
			fmt.Println("InitialContextSetupRequest received from AMF")
			if len(m.NASPdu) > 0 {
				inas.HandleNasPdu(m.NASPdu, nasCtx)
			}
		default:
			fmt.Printf("Unhandled NGAP message type: %T\n", m)
		}
	}()

	select {
	case <-done:
		fmt.Println("Response processing finished.")
	case <-time.After(30 * time.Second):
		fmt.Println("Timeout: Did not receive a response from AMF within 30 seconds. Check AMF logs.")
	}

	fmt.Println("Program finished.")
}
