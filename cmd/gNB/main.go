package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/ishidawataru/sctp"
	"gopkg.in/yaml.v3"
)

type Config struct {
	AMF AMFConfig `yaml:"amf"`
	GNB GNBConfig `yaml:"gNB"`
	UE  UEConfig  `yaml:"UE"`
}

type AMFConfig struct {
	Address string `yaml:"address"`
}

type GNBConfig struct {
	MCC   string `yaml:"mcc"`
	MNC   string `yaml:"mnc"`
	TAC   int    `yaml:"tac"`
	GNBID string `yaml:"gnbId"`
}

type UEConfig struct {
	IMSI    string `yaml:"imsi"`
	Key     string `yaml:"key"`
	RESStar string `yaml:"resStar"`
}

func loadConfig() (*Config, error) {

	yamlFile, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(yamlFile, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func main() {
	log.Println("--- gNB Emulator Starting Up ---")

	log.Println("Loading configuration from config.yaml...")
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("FATAL: Failed to load configuration: %v", err)
	}
	log.Printf("INFO: Configuration loaded successfully for MCC:%s, MNC:%s", cfg.GNB.MCC, cfg.GNB.MNC)

	amfIP, amfPortStr, err := net.SplitHostPort(cfg.AMF.Address)
	if err != nil {
		log.Fatalf("FATAL: Could not parse AMF address from config: %v", err)
	}

	log.Printf("Attempting to connect to AMF at %s:%s...", amfIP, amfPortStr)

	ip, err := net.ResolveIPAddr("ip", amfIP)
	if err != nil {
		log.Fatalf("FATAL: Failed to resolve AMF IP address: %v", err)
	}

	var amfPort int
	_, err = fmt.Sscanf(amfPortStr, "%d", &amfPort)
	if err != nil {
		log.Fatalf("FATAL: Could not parse AMF port from config: %v", err)
	}

	addr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{*ip},
		Port:    amfPort,
	}

	conn, err := sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		log.Fatalf("FATAL: Could not establish SCTP connection with AMF: %v", err)
	}
	defer conn.Close()

	log.Printf("SUCCESS: SCTP Connection Established to AMF at %s", conn.RemoteAddr())

	log.Println("INFO: Next step is to perform NG Setup...")

	log.Println("INFO: Connection is stable. The gNB will now idle.")
	select {}
}
