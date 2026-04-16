// internal/server/fingerprint/clienthello.go
package fingerprint

import (
	"encoding/binary"
	"errors"
)

// ClientHello holds fields extracted from a TLS ClientHello message.
type ClientHello struct {
	Version                   uint16
	NegotiatedVersion         uint16   // from supported_versions ext (0x002b); 0 if absent
	CipherSuites              []uint16 // excluding GREASE
	Extensions                []uint16 // all extension type IDs in order, excluding GREASE
	EllipticCurves            []uint16 // from supported_groups ext, excluding GREASE
	EllipticCurvePointFormats []uint8
	HasSNI                    bool
	SNI                       string
	FirstALPN                 string // first value from ALPN ext; empty if absent
}

var errNotClientHello = errors.New("fingerprint: not a TLS ClientHello")

// ParseClientHello parses raw bytes beginning at the TLS record header.
// Returns errNotClientHello for non-TLS data or non-ClientHello handshake types.
func ParseClientHello(data []byte) (ClientHello, error) {
	// TLS record header: 5 bytes
	if len(data) < 5 {
		return ClientHello{}, errNotClientHello
	}
	if data[0] != 0x16 { // content_type must be Handshake
		return ClientHello{}, errNotClientHello
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return ClientHello{}, errNotClientHello
	}
	body := data[5 : 5+recordLen]

	// Handshake header: 4 bytes
	if len(body) < 4 {
		return ClientHello{}, errNotClientHello
	}
	if body[0] != 0x01 { // msg_type must be ClientHello
		return ClientHello{}, errNotClientHello
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+hsLen {
		return ClientHello{}, errNotClientHello
	}
	return parseClientHelloBody(body[4 : 4+hsLen])
}

func parseClientHelloBody(data []byte) (ClientHello, error) {
	var ch ClientHello
	if len(data) < 34 { // version(2) + random(32)
		return ch, errNotClientHello
	}
	ch.Version = binary.BigEndian.Uint16(data[0:2])
	pos := 34 // skip version + random

	// session_id
	if pos >= len(data) {
		return ch, errNotClientHello
	}
	pos += 1 + int(data[pos])

	// cipher suites
	if pos+2 > len(data) {
		return ch, errNotClientHello
	}
	csLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+csLen > len(data) {
		return ch, errNotClientHello
	}
	for i := 0; i+1 < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[pos+i : pos+i+2])
		if !isGREASE(cs) {
			ch.CipherSuites = append(ch.CipherSuites, cs)
		}
	}
	pos += csLen

	// compression methods
	if pos >= len(data) {
		return ch, errNotClientHello
	}
	pos += 1 + int(data[pos])

	// extensions (optional — valid ClientHello can omit them)
	if pos+2 > len(data) {
		return ch, nil
	}
	extTotal := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	end := pos + extTotal
	if end > len(data) {
		return ch, errNotClientHello
	}

	for pos < end {
		if pos+4 > end {
			break
		}
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		extData := data[pos : pos+extLen]
		pos += extLen

		if !isGREASE(extType) {
			ch.Extensions = append(ch.Extensions, extType)
		}

		switch extType {
		case 0x0000: // SNI
			ch.HasSNI = true
			// format: list_length(2) + type(1) + name_length(2) + name
			if len(extData) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if len(extData) >= 5+nameLen {
					ch.SNI = string(extData[5 : 5+nameLen])
				}
			}
		case 0x000a: // supported_groups
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				for i := 2; i+1 < 2+listLen && i+1 < len(extData); i += 2 {
					g := binary.BigEndian.Uint16(extData[i : i+2])
					if !isGREASE(g) {
						ch.EllipticCurves = append(ch.EllipticCurves, g)
					}
				}
			}
		case 0x000b: // ec_point_formats
			if len(extData) >= 1 {
				fmtLen := int(extData[0])
				for i := 1; i <= fmtLen && i < len(extData); i++ {
					ch.EllipticCurvePointFormats = append(ch.EllipticCurvePointFormats, extData[i])
				}
			}
		case 0x0010: // ALPN
			if ch.FirstALPN == "" && len(extData) >= 4 {
				// list_length(2) + name_length(1) + name
				nameLen := int(extData[2])
				if len(extData) >= 3+nameLen {
					ch.FirstALPN = string(extData[3 : 3+nameLen])
				}
			}
		case 0x002b: // supported_versions
			// ClientHello format: list_length(1) then uint16 versions
			if len(extData) >= 1 {
				listLen := int(extData[0])
				for i := 1; i+1 < 1+listLen && i+1 < len(extData); i += 2 {
					v := binary.BigEndian.Uint16(extData[i : i+2])
					if !isGREASE(v) && v > ch.NegotiatedVersion {
						ch.NegotiatedVersion = v
					}
				}
			}
		}
	}
	return ch, nil
}

// isGREASE reports whether v is a GREASE value per RFC 8701.
// GREASE values have equal high and low bytes, both with low nibble 0xA.
func isGREASE(v uint16) bool {
	lo := byte(v)
	hi := byte(v >> 8)
	return lo == hi && lo&0x0f == 0x0a
}
