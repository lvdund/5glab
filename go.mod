module 5g-emulator

go 1.23.0

toolchain go1.24.7

require (
	github.com/ishidawataru/sctp v0.0.0-20250829011129-4b890084db30
	github.com/lvdund/ngap v1.4.13
	github.com/reogac/nas v1.2.0
	github.com/reogac/utils v1.1.15
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aead/cmac v0.0.0-20160719120800-7af84192f0b1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace 5g-emulator => .
