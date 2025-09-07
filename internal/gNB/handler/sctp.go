package handler

import (
	"fmt"
	"log"

	"github.com/ishidawataru/sctp"
)

func ConnectToAMF(amfAddress string) (*sctp.SCTPConn, error) {
	log.Printf("INFO: [SCTP] Attempting to connect to AMF at %s...", amfAddress)

	sctpAddr, err := sctp.ResolveSCTPAddr("sctp", amfAddress)
	if err != nil {
		log.Printf("ERROR: [SCTP] Failed to resolve AMF address '%s'", amfAddress)
		return nil, fmt.Errorf("failed to resolve AMF address '%s': %w", amfAddress, err)
	}
	log.Printf("INFO: [SCTP] Resolved AMF address successfully.")

	conn, err := sctp.DialSCTP("sctp", nil, sctpAddr)
	if err != nil {
		log.Printf("ERROR: [SCTP] Could not establish SCTP connection with AMF.")
		return nil, fmt.Errorf("could not establish SCTP connection with AMF: %w", err)
	}
	log.Printf("SUCCESS: [SCTP] Connection Established to AMF at %s", conn.RemoteAddr())

	info, err := conn.GetDefaultSentParam()
	if err != nil {
		conn.Close()
		log.Printf("ERROR: [SCTP] Failed to get default SCTP parameters.")
		return nil, fmt.Errorf("failed to get default SCTP parameters: %w", err)
	}
	info.PPID = 60
	err = conn.SetDefaultSentParam(info)
	if err != nil {
		conn.Close()
		log.Printf("ERROR: [SCTP] Failed to set default SCTP PPID to 60.")
		return nil, fmt.Errorf("failed to set default SCTP PPID: %w", err)
	}
	log.Printf("INFO: [SCTP] Default PPID set to 60 for NGAP.")

	return conn, nil
}
