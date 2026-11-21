package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey     string `proxy:"public-key"`
	Password      string `proxy:"password,omitempty"`
	ShortID       string `proxy:"short-id,omitempty"`
	Mldsa65Verify string `proxy:"mldsa65-verify,omitempty"`
	SpiderX       string `proxy:"spider-x,omitempty"`
	Show          bool   `proxy:"show,omitempty"`
	MasterKeyLog  string `proxy:"master-key-log,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	publicKeyValue := o.PublicKey
	if o.Password != "" {
		publicKeyValue = o.Password
	}
	if publicKeyValue != "" {
		config := new(tlsC.RealityConfig)

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(publicKeyValue)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		if o.Mldsa65Verify != "" {
			config.Mldsa65Verify, err = base64.RawURLEncoding.DecodeString(o.Mldsa65Verify)
			if err != nil || len(config.Mldsa65Verify) != 1952 {
				return nil, errors.New("invalid REALITY ML-DSA-65 verification key")
			}
		}
		config.SpiderX, config.SpiderY, err = parseRealitySpider(o.SpiderX)
		if err != nil {
			return nil, err
		}
		config.Show = o.Show
		if o.MasterKeyLog != "" && o.MasterKeyLog != "none" {
			config.KeyLogWriter, err = tlsC.OpenMasterKeyLog(o.MasterKeyLog)
			if err != nil {
				return nil, fmt.Errorf("open REALITY master key log: %w", err)
			}
		}

		return config, nil
	}
	return nil, nil
}

func parseRealitySpider(value string) (string, [10]int64, error) {
	const (
		maxPaddingBytes     = 4096
		maxParallelRequests = 16
		maxRequestsPerPath  = 100
		maxDelayMs          = 60_000
	)
	if value == "" {
		value = "/"
	}
	if value[0] != '/' {
		return "", [10]int64{}, errors.New("invalid REALITY spider-x")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", [10]int64{}, fmt.Errorf("parse REALITY spider-x: %w", err)
	}
	query := parsed.Query()
	var ranges [10]int64
	parseRange := func(name string, index int, maximum int64) error {
		values, present := query[name]
		if !present {
			return nil
		}
		if len(values) != 1 || values[0] == "" {
			return fmt.Errorf("invalid REALITY spider-x %s range", name)
		}
		parts := strings.Split(values[0], "-")
		if len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
			return fmt.Errorf("invalid REALITY spider-x %s range", name)
		}
		start, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || start < 0 || start > maximum {
			return fmt.Errorf("invalid REALITY spider-x %s range", name)
		}
		end := start
		if len(parts) == 2 {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil || end < start || end > maximum {
				return fmt.Errorf("invalid REALITY spider-x %s range", name)
			}
		}
		ranges[index] = start
		ranges[index+1] = end
		query.Del(name)
		return nil
	}
	for _, parameter := range []struct {
		name    string
		index   int
		maximum int64
	}{
		{name: "p", index: 0, maximum: maxPaddingBytes},
		{name: "c", index: 2, maximum: maxParallelRequests},
		{name: "t", index: 4, maximum: maxRequestsPerPath},
		{name: "i", index: 6, maximum: maxDelayMs},
		{name: "r", index: 8, maximum: maxDelayMs},
	} {
		if err := parseRange(parameter.name, parameter.index, parameter.maximum); err != nil {
			return "", [10]int64{}, err
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), ranges, nil
}
