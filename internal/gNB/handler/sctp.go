package handler

import (
	"fmt"
	"log"

	"github.com/ishidawataru/sctp"
)

func ConnectToAMF(amfAddress string) (*sctp.SCTPConn, error) {
	log.Printf("INFO: Attempting to connect to AMF at %s...", amfAddress)
	sctpAddr, err := sctp.ResolveSCTPAddr("sctp", amfAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve AMF address '%s': %w", amfAddress, err)
	}
	conn, err := sctp.DialSCTP("sctp", nil, sctpAddr)
	if err != nil {
		return nil, fmt.Errorf("could not establish SCTP connection with AMF: %w", err)
	}
	info, err := conn.GetDefaultSentParam()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to get default SCTP parameters: %w", err)
	}
	info.PPID = 60
	err = conn.SetDefaultSentParam(info)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set default SCTP PPID: %w", err)
	}
	log.Printf("SUCCESS: SCTP Connection Established to AMF at %s", conn.RemoteAddr())
	return conn, nil
}
