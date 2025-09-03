package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AMF AMFConfig `yaml:"amf"`
	GNB GNBConfig `yaml:"gnb"`
	UE  UEConfig  `yaml:"ue"`
}

type AMFConfig struct {
	IP   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

type GNBConfig struct {
	GNBID          uint32 `yaml:"gnbId"`
	RanUeNgapStart int    `yaml:"ranUeNgapIdStart"`
	IP             string `yaml:"ip"`
	Port           int    `yaml:"port"`
	TAC            uint32 `yaml:"tac"`
}

type UEConfig struct {
	SUPI string `yaml:"supi"`
	PLMN string `yaml:"plmn"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Failed to read config file: %v", err)
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		log.Printf("Failed to parse config file: %v", err)
		return nil, err
	}

	return &cfg, nil
}
