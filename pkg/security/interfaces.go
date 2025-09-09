package security

type UEAndNetworkAuth interface {
	K() []byte
	Opc() []byte
	Supi() string
	Mcc() string
	Mnc() string

	GetSqn() *Sqn
	SetSqn(sqn []byte)
}
