package radio

type RadioLink struct {
	UplinkChan   chan []byte
	DownlinkChan chan []byte
}

func NewRadioLink() *RadioLink {
	return &RadioLink{
		UplinkChan:   make(chan []byte, 10),
		DownlinkChan: make(chan []byte, 10),
	}
}
