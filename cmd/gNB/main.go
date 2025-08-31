package main

import (
	"fmt"
	"log"
	"os"

	"5g-emulator/internal/gNB/context"
	"5g-emulator/internal/gNB/handler"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AMF AMFConfig         `yaml:"amf"`
	GNB context.GNBConfig `yaml:"gNB"`
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
	log.Println("INFO: --- gNB Emulator Starting Up ---")
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	log.Printf("INFO: Configuration loaded for gNB Name: '%s'", cfg.GNB.GNBName)
	conn, err := handler.ConnectToAMF(cfg.AMF.Address)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	defer conn.Close()
	gnbCtx := context.NewGNBContext(&cfg.GNB, conn)
	amfName, err := handler.PerformNGSetup(gnbCtx)
	if err != nil {
		log.Fatalf("FATAL: NG Setup procedure failed: %v", err)
	}
	log.Printf("SUCCESS: NG Setup complete. Connected to AMF: '%s'", amfName)
	log.Println("INFO: gNB is now operational. Idling to keep connection alive...")
	select {}
}
