package convert

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

var (
	encRaw = base64.RawStdEncoding
	enc    = base64.StdEncoding
)

// DecodeBase64 try to decode content from the given bytes,
// which can be in base64.RawStdEncoding, base64.StdEncoding, their URL-safe
// variants or just plaintext. Whitespace and a byte order mark around the
// content are ignored.
func DecodeBase64(buf []byte) []byte {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(buf, []byte("\xef\xbb\xbf")))
	if result, err := tryDecodeBase64(trimmed); err == nil {
		return result
	}
	if result, err := tryDecodeBase64URL(trimmed); err == nil {
		return result
	}
	return buf
}

func tryDecodeBase64(buf []byte) ([]byte, error) {
	dBuf := make([]byte, encRaw.DecodedLen(len(buf)))
	n, err := encRaw.Decode(dBuf, buf)
	if err != nil {
		n, err = enc.Decode(dBuf, buf)
		if err != nil {
			return nil, err
		}
	}
	return dBuf[:n], nil
}

func tryDecodeBase64URL(buf []byte) ([]byte, error) {
	dBuf := make([]byte, base64.RawURLEncoding.DecodedLen(len(buf)))
	n, err := base64.RawURLEncoding.Decode(dBuf, buf)
	if err != nil {
		n, err = base64.URLEncoding.Decode(dBuf, buf)
		if err != nil {
			return nil, err
		}
	}
	return dBuf[:n], nil
}

func urlSafe(data string) string {
	return strings.NewReplacer("+", "-", "/", "_").Replace(data)
}

func decodeUrlSafe(data string) string {
	dcBuf, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(dcBuf)
}

func TryDecodeBase64(s string) (decoded []byte, err error) {
	if len(s)%4 == 0 {
		if decoded, err = base64.StdEncoding.DecodeString(s); err == nil {
			return
		}
		if decoded, err = base64.URLEncoding.DecodeString(s); err == nil {
			return
		}
	} else {
		if decoded, err = base64.RawStdEncoding.DecodeString(s); err == nil {
			return
		}
		if decoded, err = base64.RawURLEncoding.DecodeString(s); err == nil {
			return
		}
	}
	return nil, fmt.Errorf("invalid base64-encoded string")
}
