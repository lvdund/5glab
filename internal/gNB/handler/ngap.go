package handler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"5g-emulator/internal/gNB/context"

	"github.com/ishidawataru/sctp"
	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
	"github.com/lvdund/ngap/utils"
)

func PerformNGSetup(gnbCtx *context.GNBContext) (string, error) {
	log.Println("INFO: --- [Step 1] Building and Sending NG Setup Request ---")
	conn := gnbCtx.SCTPConn
	cfg := gnbCtx.Config

	plmnIdStruct := utils.PlmnId{Mcc: cfg.MCC, Mnc: cfg.MNC}
	plmnIDBytes := utils.PlmnIdToNgap(plmnIdStruct)

	gnbIDBytes := make([]byte, 4)
	var gnbIDUint uint32
	_, err := fmt.Sscanf(cfg.GNBID, "%x", &gnbIDUint)
	if err != nil {
		return "", fmt.Errorf("failed to parse GNBID '%s' as hex: %w", cfg.GNBID, err)
	}
	gnbIDBytes[0] = byte((gnbIDUint >> 24) & 0xFF)
	gnbIDBytes[1] = byte((gnbIDUint >> 16) & 0xFF)
	gnbIDBytes[2] = byte((gnbIDUint >> 8) & 0xFF)
	gnbIDBytes[3] = byte(gnbIDUint & 0xFF)

	tacBytes := make([]byte, 3)
	binary.BigEndian.PutUint16(tacBytes[1:], uint16(cfg.TAC))

	ngSetupRequest := ies.NGSetupRequest{
		GlobalRANNodeID: ies.GlobalRANNodeID{
			Choice: ies.GlobalRANNodeIDPresentGlobalgnbId,
			GlobalGNBID: &ies.GlobalGNBID{
				PLMNIdentity: plmnIDBytes,
				GNBID: ies.GNBID{
					Choice: ies.GNBIDPresentGnbId,
					GNBID: &aper.BitString{
						Bytes:   gnbIDBytes,
						NumBits: uint64(len(gnbIDBytes) * 8),
					},
				},
			},
		},
		RANNodeName: []byte(cfg.GNBName),
		SupportedTAList: []ies.SupportedTAItem{
			{
				TAC: tacBytes,
				BroadcastPLMNList: []ies.BroadcastPLMNItem{
					{
						PLMNIdentity:        plmnIDBytes,
						TAISliceSupportList: []ies.SliceSupportItem{},
					},
				},
			},
		},
		DefaultPagingDRX: ies.PagingDRX{Value: ies.PagingDRXV128},
	}

	var buffer bytes.Buffer
	err = ngSetupRequest.Encode(&buffer)
	if err != nil {
		return "", fmt.Errorf("failed to encode NG Setup Request: %w", err)
	}
	encodedPDU := buffer.Bytes()

	info := &sctp.SndRcvInfo{
		Stream: 0,
		PPID:   60,
	}

	_, err = conn.SCTPWrite(encodedPDU, info)
	if err != nil {
		return "", fmt.Errorf("failed to send NG Setup Request over SCTP: %w", err)
	}
	log.Println("INFO: NG Setup Request sent successfully.")
	log.Println("INFO: --- [Step 2] Waiting for NG Setup Response ---")
	readBuffer := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.SCTPRead(readBuffer)
	if err != nil {
		return "", fmt.Errorf("failed to read from SCTP connection: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	response, err, _ := ngap.NgapDecode(readBuffer[:n])
	if err != nil {
		return "", fmt.Errorf("failed to decode NGAP response: %w", err)
	}

	if response.Present != ies.NgapPduSuccessfulOutcome {
		return "", fmt.Errorf("NG Setup procedure was rejected by AMF")
	}

	ngSetupResponse, ok := response.Message.Msg.(*ies.NGSetupResponse)
	if !ok || ngSetupResponse == nil {
		return "", fmt.Errorf("received malformed NG Setup Response from AMF")
	}

	amfName := ngSetupResponse.AMFName
	relativeCapacity := ngSetupResponse.RelativeAMFCapacity
	log.Printf("INFO: Received NG Setup Response. AMF Name: '%s', Relative Capacity: %d", amfName, relativeCapacity)

	return string(amfName), nil
}
