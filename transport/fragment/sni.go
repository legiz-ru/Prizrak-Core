package fragment

import (
	"encoding/binary"
	"strings"

	"github.com/metacubex/randv2"
)

const (
	recordHeaderLen  = 5
	recordHandshake  = 22
	maxRecordPayload = 1<<14 + 2048 // TLSCiphertext limit, generous for a ClientHello
)

// handshakeRecordLen returns the length of the TLS handshake record b starts
// with, header included, or 0 if b does not start with one.
func handshakeRecordLen(b []byte) int {
	if len(b) < recordHeaderLen || b[0] != recordHandshake || b[1] != 3 {
		return 0
	}
	l := int(binary.BigEndian.Uint16(b[3:5]))
	if l == 0 || l > maxRecordPayload {
		return 0
	}
	return recordHeaderLen + l
}

// recordStart reports whether b, shorter than a record header, may be the
// start of a TLS handshake record.
func recordStart(b []byte) bool {
	return len(b) < recordHeaderLen && len(b) > 0 && b[0] == recordHandshake && (len(b) < 2 || b[1] == 3)
}

// serverNameIndex finds the host name in a complete ClientHello record and
// returns its offset in b and its length, or -1. The walk follows
// IndexTLSServerName of sing-box's common/tlsfragment.
func serverNameIndex(b []byte) (int, int) {
	recordLen := handshakeRecordLen(b)
	if recordLen == 0 || len(b) < recordLen {
		return -1, 0
	}
	hs := b[recordHeaderLen:recordLen]
	// handshake header (4), client version (2), random (32), session id length (1)
	if len(hs) < 4+2+32+1 || hs[0] != 1 {
		return -1, 0
	}
	if int(hs[1])<<16|int(hs[2])<<8|int(hs[3]) != len(hs)-4 {
		return -1, 0
	}
	i := 4 + 2 + 32
	i += 1 + int(hs[i]) // session id
	if len(hs) < i+2 {
		return -1, 0
	}
	i += 2 + int(binary.BigEndian.Uint16(hs[i:])) // cipher suites
	if len(hs) < i+1 {
		return -1, 0
	}
	i += 1 + int(hs[i]) // compression methods
	if len(hs) < i+2 {
		return -1, 0
	}
	end := i + 2 + int(binary.BigEndian.Uint16(hs[i:]))
	i += 2
	if len(hs) < end {
		return -1, 0
	}
	for i+4 <= end {
		typ := binary.BigEndian.Uint16(hs[i:])
		l := int(binary.BigEndian.Uint16(hs[i+2:]))
		i += 4
		if i+l > end {
			return -1, 0
		}
		if typ == 0 { // server_name
			ext := hs[i : i+l]
			// list length (2), name type (1), name length (2)
			if len(ext) < 5 || ext[2] != 0 {
				return -1, 0
			}
			n := int(binary.BigEndian.Uint16(ext[3:]))
			if 5+n > len(ext) || n == 0 {
				return -1, 0
			}
			return recordHeaderLen + i + 5, n
		}
		i += l
	}
	return -1, 0
}

// sniCuts returns the offsets in b to cut at: one random point inside every
// label of the server name but the top-level domain, so no piece carries the
// whole name.
func sniCuts(b []byte) []int {
	at, n := serverNameIndex(b)
	if at < 0 {
		return nil
	}
	labels := strings.Split(string(b[at:at+n]), ".")
	if len(labels) > 1 {
		labels = labels[:len(labels)-1]
	}
	var cuts []int
	pos := at
	for _, label := range labels {
		if len(label) > 1 {
			cuts = append(cuts, pos+1+randv2.IntN(len(label)-1))
		} else if len(label) == 1 && pos > at {
			cuts = append(cuts, pos)
		}
		pos += len(label) + 1
	}
	return cuts
}
