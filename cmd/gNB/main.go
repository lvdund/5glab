package main

import (
	"fmt"
	"log"
	"net"
	"os" // We need the 'os' package to read files

	"github.com/ishidawataru/sctp"
	"gopkg.in/yaml.v3" // Import the YAML library
)

// --- Structs to hold our configuration ---

// Config is the top-level structure that matches the YAML file.
type Config struct {
	AMF AMFConfig `yaml:"amf"`
	GNB GNBConfig `yaml:"gNB"`
	UE  UEConfig  `yaml:"UE"`
}

// AMFConfig holds the configuration for the AMF we connect to.
type AMFConfig struct {
	Address string `yaml:"address"`
}

// GNBConfig holds the configuration for our gNB emulator.
type GNBConfig struct {
	MCC   string `yaml:"mcc"`
	MNC   string `yaml:"mnc"`
	TAC   int    `yaml:"tac"`
	GNBID string `yaml:"gnbId"`
}

// UEConfig holds the configuration for our UE emulator.
type UEConfig struct {
	IMSI    string `yaml:"imsi"`
	Key     string `yaml:"key"`
	RESStar string `yaml:"resStar"`
}

// --- Configuration Loading Function ---

// loadConfig reads and parses the configuration from config.yaml
func loadConfig() (*Config, error) {
	// The path is relative to the project root
	// Note: We run `go run ./cmd/gNB`, so the working directory is the project root.
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

// --- Main Application ---

func main() {
	log.Println("--- gNB Emulator Starting Up ---")

	// --- Step A: Load Configuration ---
	log.Println("Loading configuration from config.yaml...")
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("FATAL: Failed to load configuration: %v", err)
	}
	log.Printf("INFO: Configuration loaded successfully for MCC:%s, MNC:%s", cfg.GNB.MCC, cfg.GNB.MNC)

	// --- Step 0: Establish SCTP Connection ---

	// Split the AMF address into IP and Port
	amfIP, amfPortStr, err := net.SplitHostPort(cfg.AMF.Address)
	if err != nil {
		log.Fatalf("FATAL: Could not parse AMF address from config: %v", err)
	}

	log.Printf("Attempting to connect to AMF at %s:%s...", amfIP, amfPortStr)

	// Resolve the IP address for the SCTP connection.
	ip, err := net.ResolveIPAddr("ip", amfIP)
	if err != nil {
		log.Fatalf("FATAL: Failed to resolve AMF IP address: %v", err)
	}

	// The port needs to be an integer
	var amfPort int
	_, err = fmt.Sscanf(amfPortStr, "%d", &amfPort)
	if err != nil {
		log.Fatalf("FATAL: Could not parse AMF port from config: %v", err)
	}

	// Create the full SCTP address structure.
	addr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{*ip},
		Port:    amfPort,
	}

	// Dial the SCTP connection.
	conn, err := sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		log.Fatalf("FATAL: Could not establish SCTP connection with AMF: %v", err)
	}
	defer conn.Close()

	log.Printf("SUCCESS: SCTP Connection Established to AMF at %s", conn.RemoteAddr())

	// --- Placeholder for Step 1: NG Setup ---
	log.Println("INFO: Next step is to perform NG Setup...")

	log.Println("INFO: Connection is stable. The gNB will now idle.")
	select {} // Block forever
}
