module github.com/aero-protocol/aero-edge

go 1.25.0

// Frozen snapshot: AERO Edge Server v1.0.0
// Source freeze path: grok/aero/server

require (
	github.com/aero-protocol/proto v0.0.0
	github.com/quic-go/quic-go v0.59.1
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.56.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/aero-protocol/proto => ../proto

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	modernc.org/libc v1.75.7 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	modernc.org/sqlite v1.59.0 // indirect
)
