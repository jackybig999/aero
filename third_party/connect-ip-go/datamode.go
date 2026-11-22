// AERO fork of github.com/quic-go/connect-ip-go v0.4.0 (MIT, see LICENSE).
// This file is an addition: see FORK.md for the list of changes.

package connectip

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// DataMode selects how IP packets are carried between the two endpoints of a Conn.
//
// Both endpoints of one CONNECT-IP request MUST use the same mode. The mode is not
// negotiated on the wire; the application decides it from out-of-band information
// (for example a request header) before creating the Conn.
type DataMode uint8

const (
	// DataModeDatagram carries each IP packet in a QUIC DATAGRAM frame
	// (RFC 9484 Section 6, RFC 9221). Packets may be lost or reordered. This is the default.
	DataModeDatagram DataMode = iota

	// DataModeCapsule carries each IP packet in a DATAGRAM capsule (type 0x00,
	// RFC 9297 Section 3.5) on the request stream. The stream is reliable and ordered,
	// so packets are neither lost nor reordered, at the cost of head-of-line blocking
	// among all packets of this Conn (RFC 9484 Section 10: nested congestion control).
	//
	// QUIC DATAGRAM support must still be negotiated on the connection: this fork does not
	// treat capsule mode as a fallback for peers without datagram support.
	//
	// Control capsules (address assignment, route advertisement, ...) share the same stream
	// with the data capsules. The receiver must therefore keep calling ReadPacket, otherwise
	// control capsules queued behind data stall (RFC 9297 Section 3.2). Further requirements:
	//   - ReadPacket and WritePacket must run in different goroutines; with both flow-control
	//     windows full, a single goroutine doing both would wait on itself.
	//   - While the application does not call ReadPacket, the stream reader is blocked once the
	//     receive queue is full, so a FIN or reset from the peer is only noticed after Close.
	//   - When the peer closes the stream cleanly, packets already received are still returned
	//     by ReadPacket before it reports the close.
	DataModeCapsule
)

func (m DataMode) String() string {
	switch m {
	case DataModeDatagram:
		return "datagram"
	case DataModeCapsule:
		return "capsule"
	default:
		return fmt.Sprintf("DataMode(%d)", uint8(m))
	}
}

const (
	// capsuleTypeDatagram is the DATAGRAM capsule type (RFC 9297 Section 3.5).
	capsuleTypeDatagram http3.CapsuleType = 0x00

	// maxDataCapsuleSize bounds the value of one DATAGRAM capsule: Context ID (1 byte for 0)
	// plus the largest IP packet (65535 bytes).
	maxDataCapsuleSize = 1 + 65535

	// maxQueuedDataWrites bounds queued data capsules per Conn. It is lower than maxQueuedCapsules
	// so that control capsules always find room: a full data queue blocks WritePacket
	// (back-pressure) instead of closing the Conn.
	maxQueuedDataWrites = maxQueuedCapsules / 4

	// maxQueuedDataReads bounds received data packets waiting for ReadPacket. When full, the
	// stream reader stops reading, and QUIC flow control slows down the sender.
	maxQueuedDataReads = maxQueuedCapsules
)

// appendDataCapsule appends a DATAGRAM capsule whose value is payload
// (the HTTP Datagram Payload: Context ID followed by the IP packet).
func appendDataCapsule(b []byte, payload []byte) []byte {
	b = quicvarint.Append(b, uint64(capsuleTypeDatagram))
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

// splitDataPayload splits an HTTP Datagram Payload into Context ID and IP packet.
func splitDataPayload(payload []byte) (contextID uint64, packet []byte, err error) {
	contextID, n, err := quicvarint.Parse(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("connect-ip: malformed datagram capsule: %w", err)
	}
	return contextID, payload[n:], nil
}

// ProxyWithMode is like [Proxy.Proxy] but selects how IP packets are carried.
func (s *Proxy) ProxyWithMode(w http.ResponseWriter, _ *ProxyRequest, mode DataMode) (*Conn, error) {
	if mode != DataModeDatagram && mode != DataModeCapsule {
		return nil, errors.New("connect-ip: unknown data mode")
	}
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	str := w.(http3.HTTPStreamer).HTTPStream()
	return newProxiedConnMode(str, nil, mode), nil
}

// DialWithMode is like [ClientConn.Dial] but selects how IP packets are carried.
// The proxy must use the same mode for this request.
func (c *ClientConn) DialWithMode(req *Request, mode DataMode) (*Conn, *http.Response, error) {
	if mode != DataModeDatagram && mode != DataModeCapsule {
		return nil, nil, errors.New("connect-ip: unknown data mode")
	}
	return c.dialMode(req, nil, mode)
}

// DataMode returns how this Conn carries IP packets.
func (c *Conn) DataMode() DataMode { return c.mode }

// DroppedModeMismatch returns how many data capsules were dropped because this Conn
// is in datagram mode. A nonzero value means the peer uses a different mode.
func (c *Conn) DroppedModeMismatch() uint64 { return c.droppedMismatch.Load() }
