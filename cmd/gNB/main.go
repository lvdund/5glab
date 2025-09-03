package main

import (
	ue_context "5g-emulator/internal/UE/context"
	gnb_context "5g-emulator/internal/gNB/context"
	gnb_handler "5g-emulator/internal/gNB/handler"
	nas_builder "5g-emulator/pkg/nas"

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

	conn, err := gnb_handler.ConnectToAMF(cfg.AMF.Address)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	defer conn.Close()

	gnbCtx := gnb_context.NewGNBContext(&cfg.GNB, conn)
	_, err = gnb_handler.PerformNGSetup(gnbCtx)
	if err != nil {
		log.Fatalf("FATAL: NG Setup procedure failed: %v", err)
	}
	log.Println("SUCCESS: gNB is operational.")
	time.Sleep(1 * time.Second)

	ueCtx := ue_context.NewUEContext(&cfg.UE)
	gnbCtx.SetUEContext(ueCtx)

	nasPDU, err := nas_builder.BuildRegistrationRequest(&cfg.UE)
	if err != nil {
		log.Fatalf("FATAL: [UE] Failed to build NAS message: %v", err)
	}

	err = gnb_handler.HandleInitialUEMessage(gnbCtx, nasPDU)
	if err != nil {
		log.Fatalf("FATAL: [gNB] Failed to send Initial UE Message: %v", err)
	}

	log.Println("INFO: --- [Step 4] Waiting for AMF to respond (e.g., Authentication Request) ---")
	select {}
}
