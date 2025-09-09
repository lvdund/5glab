package main

import (
	ue_context "5g-emulator/internal/UE/context"
	ue_handler "5g-emulator/internal/UE/handler"
	gnb_context "5g-emulator/internal/gNB/context"
	gnb_handler "5g-emulator/internal/gNB/handler"
	"5g-emulator/internal/radio"

	"fmt"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AMF AMFConfig             `yaml:"amf"`
	GNB gnb_context.GNBConfig `yaml:"gNB"`
	UE  ue_context.UEConfig   `yaml:"ue"`
}

type AMFConfig struct {
	Address string `yaml:"address"`
}

func loadConfig() (*Config, error) {
	yamlFile, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, fmt.Errorf("could not read config.yaml: %w", err)
	}
	var cfg Config
	err = yaml.Unmarshal(yamlFile, &cfg)
	if err != nil {
		return nil, fmt.Errorf("could not parse config.yaml: %w", err)
	}
	return &cfg, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("INFO: --- Emulator Orchestrator Starting Up ---")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	radioLink := radio.NewRadioLink()

	conn, err := gnb_handler.ConnectToAMF(cfg.AMF.Address)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	defer conn.Close()

	gnbCtx := gnb_context.NewGNBContext(&cfg.GNB, conn, radioLink)
	_, err = gnb_handler.PerformNGSetup(gnbCtx)
	if err != nil {
		log.Fatalf("FATAL: NG Setup procedure failed: %v", err)
	}
	log.Println("SUCCESS: gNB is operational.")
	time.Sleep(1 * time.Second)

	ueCtx, err := ue_context.NewUEContext(&cfg.UE, cfg.GNB.MCC, cfg.GNB.MNC, radioLink)
	if err != nil {
		log.Fatalf("FATAL: Failed to create UE context: %v", err)
	}
	gnbCtx.SetUEContext(ueCtx)

	nasPDU, err := ue_handler.BuildRegistrationRequest(ueCtx)
	if err != nil {
		log.Fatalf("FATAL: [UE] Failed to build NAS message: %v", err)
	}
	err = gnb_handler.HandleInitialUEMessage(gnbCtx, nasPDU)
	if err != nil {
		log.Fatalf("FATAL: [gNB] Failed to send Initial UE Message: %v", err)
	}

	go gnb_handler.ListenForMessages(gnbCtx)
	go ue_handler.ListenForDownlink(ueCtx)

	log.Println("INFO: --- [Step 4] Now actively listening for all messages ---")
	select {}
}
