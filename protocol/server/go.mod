module github.com/aero-protocol/aero-edge

go 1.25.0

// Frozen snapshot: AERO Edge Server v1.0.0
// Source freeze path: grok/aero/server

require (
	github.com/aero-protocol/proto v0.0.0
	github.com/quic-go/quic-go v0.59.1
	golang.org/x/crypto v0.41.0
	golang.org/x/net v0.43.0
	google.golang.org/protobuf v1.34.1
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/aero-protocol/proto => ./public/proto

require (
	github.com/kr/text v0.2.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)
