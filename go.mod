module github.com/go-i2p/common

go 1.26.3

require (
	github.com/go-i2p/crypto v0.1.60000-0.20260701135847-3ade996b68a0
	github.com/go-i2p/logger v0.1.60000-0.20260701134448-2648c3b0e040
	github.com/go-i2p/red25519 v0.0.0-20260908204607-9444de34c638
	github.com/samber/oops v1.23.1
	github.com/stretchr/testify v1.12.1
	go.step.sm/crypto v0.90.0
	golang.org/x/crypto v0.57.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-i2p/elgamal v0.1.60000-0.20260701131626-b5c8141026fc // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

// replace github.com/go-i2p/crypto => ../crypto

// replace github.com/go-i2p/logger => ../logger

//replace github.com/go-i2p/logger => /home/idk/go/src/github.com/go-i2p/logger

//replace github.com/go-i2p/elgamal => /home/idk/go/src/github.com/go-i2p/elgamal

//replace github.com/go-i2p/su3 => /home/idk/go/src/github.com/go-i2p/su3

//replace github.com/go-i2p/crypto => /home/idk/go/src/github.com/go-i2p/crypto

//replace github.com/go-i2p/go-i2p => /home/idk/go/src/github.com/go-i2p/go-i2p

retract (
	v0.1.59999
	v0.1.5999
	v0.1.599
)
