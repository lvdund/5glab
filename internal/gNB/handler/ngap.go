package handler

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
						PLMNIdentity: plmnIDBytes,
						TAISliceSupportList: []ies.SliceSupportItem{
							{
								SNSSAI: ies.SNSSAI{
									SST: []byte{1},
								},
							},
						},
					},
				},
			},
		},
		DefaultPagingDRX: ies.PagingDRX{Value: ies.PagingDRXV128},
	}

	encodedPDU, err := ngap.NgapEncode(&ngSetupRequest)
	if err != nil {
		return "", fmt.Errorf("failed to encode NG Setup Request: %w", err)
	}

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

func HandleInitialUEMessage(gnbCtx *context.GNBContext, nasPDU []byte) error {
	log.Println("INFO: --- [gNB - Step 3b] Building and Sending Initial UE Message ---")

	plmnIdStruct := utils.PlmnId{Mcc: gnbCtx.Config.MCC, Mnc: gnbCtx.Config.MNC}
	plmnIDBytes := utils.PlmnIdToNgap(plmnIdStruct)

	gnbIDBytes, err := hex.DecodeString(gnbCtx.Config.GNBID)
	if err != nil {
		return fmt.Errorf("could not convert gNB ID for location info: %w", err)
	}

	tacString := fmt.Sprintf("%06x", gnbCtx.Config.TAC)
	taiStruct := utils.Tai{PlmnId: &plmnIdStruct, Tac: tacString}
	taiNgap := utils.TaiToNgap(taiStruct)
	tacBytes := taiNgap.TAC

	initialUEMessage := ies.InitialUEMessage{
		RANUENGAPID: gnbCtx.RanUeNgapID,
		NASPDU:      nasPDU,

		UserLocationInformation: ies.UserLocationInformation{
			Choice: ies.UserLocationInformationPresentUserlocationinformationnr,
			UserLocationInformationNR: &ies.UserLocationInformationNR{
				NRCGI: ies.NRCGI{
					PLMNIdentity: plmnIDBytes,
					NRCellIdentity: aper.BitString{
						Bytes:   append(gnbIDBytes, 0x0, 0x0),
						NumBits: 36,
					},
				},
				TAI: ies.TAI{
					PLMNIdentity: plmnIDBytes,
					TAC:          tacBytes,
				},
			},
		},

		RRCEstablishmentCause: ies.RRCEstablishmentCause{Value: ies.RRCEstablishmentCauseMosignalling},
		UEContextRequest:      &ies.UEContextRequest{Value: ies.UEContextRequestRequested},
	}

	var buffer bytes.Buffer
	err = initialUEMessage.Encode(&buffer)
	if err != nil {
		return fmt.Errorf("failed to encode Initial UE Message: %w", err)
	}
	encodedPDU := buffer.Bytes()

	info := &sctp.SndRcvInfo{
		Stream: 0,
		PPID:   60,
	}
	_, err = gnbCtx.SCTPConn.SCTPWrite(encodedPDU, info)
	if err != nil {
		return fmt.Errorf("failed to send Initial UE Message over SCTP: %w", err)
	}

	log.Println("INFO: Initial UE Message sent successfully.")
	return nil
}

func ListenForMessages(gnbCtx *context.GNBContext) {
	conn := gnbCtx.SCTPConn
	buffer := make([]byte, 8192)

	log.Println("INFO: gNB is now listening for incoming NGAP messages...")

	for {
		n, _, err := conn.SCTPRead(buffer)
		if err != nil {

			log.Printf("ERROR: Failed to read from SCTP connection: %v. Exiting listener.", err)
			return
		}

		pdu, err, _ := ngap.NgapDecode(buffer[:n])
		if err != nil {
			log.Printf("ERROR: Failed to decode NGAP message: %v", err)
			continue
		}

		switch pdu.Present {
		case ies.NgapPduInitiatingMessage:
			procCode := pdu.Message.ProcedureCode.Value

			switch procCode {
			case ies.ProcedureCode_DownlinkNASTransport:
				log.Println("INFO: --- [Step 4] Received Downlink NAS Transport from AMF ---")

				downlinkNasTransport, ok := pdu.Message.Msg.(*ies.DownlinkNASTransport)
				if !ok {
					log.Println("ERROR: Could not type assert to DownlinkNASTransport.")
					continue
				}

				nasPDU := downlinkNasTransport.NASPDU
				log.Printf("INFO: Extracted NAS PDU, forwarding to UE (length: %d bytes)", len(nasPDU))

				gnbCtx.DownlinkChan <- nasPDU

			default:
				log.Printf("WARN: Received unhandled Initiating Message (Procedure Code: %d)", procCode)
			}

		case ies.NgapPduSuccessfulOutcome:
			procCode := pdu.Message.ProcedureCode.Value
			log.Printf("INFO: Received Successful Outcome (Procedure Code: %d)", procCode)

		case ies.NgapPduUnsuccessfulOutcome:
			procCode := pdu.Message.ProcedureCode.Value
			log.Printf("INFO: Received Unsuccessful Outcome (Procedure Code: %d)", procCode)
		}
	}
}
