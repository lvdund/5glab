package model

type AMF struct {
	Ip   string `yaml:"ip"`
	Port int    `yaml:"port"`
}
type ControlIF struct {
	Ip   string `yaml:"ip"`
	Port int    `yaml:"port"`
}
type DataIF struct {
	Ip   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

type GnbInfo struct {
	Tac              string   `yaml:"tac"`
	GnbId            string   `yaml:"gnbid"`
	Plmn             Plmn     `yaml:"plmn"`
	SliceSupportList []Snssai `yaml:"slicesupportlist"`
}
type Plmn struct {
	Mcc string `yaml:"mcc"`
	Mnc string `yaml:"mnc"`
}
type Snssai struct {
	Sst string `yaml:"sst"`
	Sd  string `yaml:"sd"`
}
