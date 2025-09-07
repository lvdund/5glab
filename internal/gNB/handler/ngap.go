package handler

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"5g-emulator/internal/gNB/context"
	"5g-emulator/pkg/logger"

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

	logger.LogMessageContent("gNB -> AMF: NGAP NGSetupRequest", &ngSetupRequest)

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

	logger.LogMessageContent("AMF -> gNB: NGAP NGSetupResponse", response.Message.Msg)

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
	logger.LogMessageContent("gNB -> AMF: NGAP InitialUEMessage", &initialUEMessage)

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
	log.Println("INFO: [gNB] Starting bidirectional message listener...")

	sctpReadChan := make(chan []byte, 10)

	go func(conn *sctp.SCTPConn, ch chan<- []byte) {
		buffer := make([]byte, 8192)
		for {
			n, _, err := conn.SCTPRead(buffer)
			if err != nil {
				log.Printf("ERROR: [SCTP Listener] Failed to read from SCTP: %v. Closing listener.", err)
				close(ch)
				return
			}
			data := make([]byte, n)
			copy(data, buffer[:n])
			ch <- data
		}
	}(gnbCtx.SCTPConn, sctpReadChan)

	for {
		select {
		case amfData, ok := <-sctpReadChan:
			if !ok {
				log.Println("ERROR: [gNB] SCTP channel was closed. Terminating.")
				return
			}

			pdu, err, _ := ngap.NgapDecode(amfData)
			if err != nil {
				log.Printf("ERROR: [gNB] Failed to decode NGAP message from AMF: %v", err)
				continue
			}

			if pdu.Present == ies.NgapPduInitiatingMessage &&
				pdu.Message.ProcedureCode.Value == ies.ProcedureCode_DownlinkNASTransport {

				log.Println("INFO: --- [Step 4] Received Downlink NAS Transport from AMF ---")

				downlinkNasTransport, ok := pdu.Message.Msg.(*ies.DownlinkNASTransport)
				if !ok {
					log.Println("ERROR: [gNB] Could not type assert to DownlinkNASTransport.")
					continue
				}

				gnbCtx.AmfUeNgapID = downlinkNasTransport.AMFUENGAPID
				log.Printf("INFO: [gNB] Learned AMF UE NGAP ID: %d", gnbCtx.AmfUeNgapID)

				gnbCtx.Radio.DownlinkChan <- downlinkNasTransport.NASPDU
			} else {
				log.Printf("WARN: [gNB] Received unhandled message from AMF (Present: %d, ProcCode: %d)",
					pdu.Present, pdu.Message.ProcedureCode.Value)
			}

		case nasPDU := <-gnbCtx.Radio.UplinkChan:
			log.Println("INFO: --- [Step 5b] Received NAS message from UE, forwarding to AMF ---")
			err := HandleUplinkNasTransport(gnbCtx, nasPDU)
			if err != nil {
				log.Printf("ERROR: [gNB] Failed to send Uplink NAS Transport: %v", err)
			}
		}
	}
}

func HandleUplinkNasTransport(gnbCtx *context.GNBContext, nasPDU []byte) error {
	log.Println("INFO: --- [gNB] Building Uplink NAS Transport ---")

	plmnIdStruct := utils.PlmnId{Mcc: gnbCtx.Config.MCC, Mnc: gnbCtx.Config.MNC}
	plmnIDBytes := utils.PlmnIdToNgap(plmnIdStruct)

	gnbIDBytes, err := hex.DecodeString(gnbCtx.Config.GNBID)
	if err != nil {
		return fmt.Errorf("could not convert gNB ID for location info: %w", err)
	}

	tacBytes := make([]byte, 3)
	binary.BigEndian.PutUint16(tacBytes[1:], uint16(gnbCtx.Config.TAC))

	uplinkNasTransport := ies.UplinkNASTransport{
		AMFUENGAPID: gnbCtx.AmfUeNgapID,
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
	}

	var buffer bytes.Buffer
	err = uplinkNasTransport.Encode(&buffer)
	if err != nil {
		return fmt.Errorf("failed to encode Uplink NAS Transport: %w", err)
	}
	encodedPDU := buffer.Bytes()

	logger.LogMessageContent("gNB -> AMF: NGAP UplinkNASTransport", &uplinkNasTransport)

	info := &sctp.SndRcvInfo{
		Stream: 0,
		PPID:   60,
	}
	_, err = gnbCtx.SCTPConn.SCTPWrite(encodedPDU, info)
	if err != nil {
		return fmt.Errorf("failed to send Uplink NAS Transport over SCTP: %w", err)
	}

	log.Println("INFO: Uplink NAS Transport sent successfully.")
	return nil
}
