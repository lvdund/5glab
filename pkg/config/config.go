// File: pkg/config/config.go
// Update struct để match với format YAML cũ

package config

import (
	"os"
	"gopkg.in/yaml.v2"
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
	// Hỗ trợ cả 2 format: gnbId và gnb_id
	GnbId            string `yaml:"gnbId"`            // Format cũ
	GnbIdAlt         string `yaml:"gnb_id"`           // Format mới
	RanUeNgapIdStart uint64 `yaml:"ranUeNgapIdStart"` // Format cũ
	RanUeNgapIdAlt   uint64 `yaml:"ran_ue_ngap_id_start"` // Format mới
	IP               string `yaml:"ip"`
	Port             int    `yaml:"port"`
	TAC              uint32 `yaml:"tac"`
	
}

type UEConfig struct {
	SUPI string `yaml:"supi"`
	PLMN string `yaml:"plmn"`
	Key  string `yaml:"key"`
	OPC  string `yaml:"opc"`
}

func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Normalize: Ưu tiên format cũ nếu có
	if cfg.GNB.GnbId != "" {
		// Format cũ
	} else if cfg.GNB.GnbIdAlt != "" {
		cfg.GNB.GnbId = cfg.GNB.GnbIdAlt
	}

	if cfg.GNB.RanUeNgapIdStart != 0 {
		// Format cũ
	} else if cfg.GNB.RanUeNgapIdAlt != 0 {
		cfg.GNB.RanUeNgapIdStart = cfg.GNB.RanUeNgapIdAlt
	}

	return &cfg, nil
}