// Package option reads a finalmask block of the config into the mask
// chain; the mask types it knows are the registry of the port.
package option

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/mihomo/transport/finalmask/custom"
	"github.com/metacubex/mihomo/transport/finalmask/fragment"
	"github.com/metacubex/mihomo/transport/finalmask/noise"
	"github.com/metacubex/mihomo/transport/finalmask/sudoku"
	"github.com/metacubex/mihomo/transport/finalmask/udphop"
	"github.com/metacubex/mihomo/transport/finalmask/xdns"
	"github.com/metacubex/mihomo/transport/finalmask/xicmp"
	"github.com/metacubex/mihomo/transport/finalmask/xmc"
)

// Option is the finalmask block of a vless or trojan proxy or listener, as
// in Xray-core: TCP masks wrap the stream under TLS, UDP masks wrap the QUIC
// socket of xhttp over HTTP/3. Each entry has a type and the mask's own
// settings beside it (or under settings, as Xray nests them); the first
// entry is the outermost mask, the last one is what the network sees.
type Option struct {
	TCP []map[string]any `proxy:"tcp,omitempty" inbound:"tcp,omitempty" yaml:"tcp,omitempty" json:"tcp,omitempty"`
	UDP []map[string]any `proxy:"udp,omitempty" inbound:"udp,omitempty" yaml:"udp,omitempty" json:"udp,omitempty"`
}

var decoder = structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})

// maskEntry splits an entry into its type and the settings to decode.
func maskEntry(entry map[string]any) (string, map[string]any, error) {
	typ, _ := entry["type"].(string)
	typ = strings.ToLower(strings.TrimSpace(typ))
	if typ == "" {
		return "", nil, errors.New("finalmask: mask without a type")
	}
	settings := make(map[string]any, len(entry))
	for k, v := range entry {
		if k == "type" {
			continue
		}
		settings[k] = v
	}
	if nested, ok := settings["settings"]; ok && len(settings) == 1 {
		switch nested := nested.(type) {
		case map[string]any:
			settings = nested
		case map[any]any:
			settings = make(map[string]any, len(nested))
			for k, v := range nested {
				settings[fmt.Sprint(k)] = v
			}
		case nil:
			settings = map[string]any{}
		default:
			return "", nil, fmt.Errorf("finalmask: settings of %s must be a map", typ)
		}
	}
	return typ, normalizeKeys(settings).(map[string]any), nil
}

// normalizeKeys brings the camelCase keys of Xray's JSON (randRange,
// remoteIPs, texturesValue) to the kebab-case of the option tags, nested
// maps and lists included, so a block copied from an Xray config or carried
// by a share link decodes like one written for the YAML. Keys without
// capitals, kebab-case or snake_case, pass as they are.
func normalizeKeys(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[kebabKey(k)] = normalizeKeys(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[kebabKey(fmt.Sprint(k))] = normalizeKeys(val)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, val := range v {
			out[i] = normalizeKeys(val)
		}
		return out
	case float64:
		// JSON numbers arrive as float64; a whole one decodes as an
		// integer, so "delay": 0 reads as the range 0, not "0E+00".
		if v == math.Trunc(v) && math.Abs(v) < 1<<53 {
			return int64(v)
		}
	}
	return v
}

// kebabKey puts a dash before a capital that follows a lower-case letter or
// a digit and lowers the key: randRange to rand-range, remoteIPs to
// remote-ips (a run of capitals stays one word).
func kebabKey(k string) string {
	var b strings.Builder
	prev := rune(0)
	for _, r := range k {
		if unicode.IsUpper(r) {
			if unicode.IsLower(prev) || unicode.IsDigit(prev) {
				b.WriteByte('-')
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
		prev = r
	}
	return b.String()
}

func decodeMask(settings map[string]any, option any) error {
	if len(settings) == 0 {
		return nil
	}
	return decoder.Decode(settings, option)
}

func BuildTCPMask(entry map[string]any) (finalmask.TCPMask, error) {
	typ, settings, err := maskEntry(entry)
	if err != nil {
		return nil, err
	}
	switch typ {
	case "fragment":
		var o fragment.Option
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return fragment.New(o)
	case "header-custom":
		var o custom.TCPOption
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return custom.NewTCP(o)
	case "sudoku":
		var o sudoku.Config
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return sudoku.New(o)
	case "xmc":
		var o xmc.Option
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return xmc.New(o)
	case "mkcp-legacy", "salamander", "realm", "noise", "udphop", "xdns", "xicmp":
		return nil, fmt.Errorf("finalmask: %s is not a TCP mask", typ)
	default:
		return nil, fmt.Errorf("finalmask: unknown TCP mask %q, want fragment, header-custom, sudoku or xmc", typ)
	}
}

func BuildUDPMask(entry map[string]any) (finalmask.UDPMask, error) {
	typ, settings, err := maskEntry(entry)
	if err != nil {
		return nil, err
	}
	switch typ {
	case "noise":
		var o noise.Option
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return noise.New(o)
	case "header-custom":
		var o custom.UDPOption
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return custom.NewUDP(o)
	case "sudoku":
		var o sudoku.Config
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return sudoku.New(o)
	case "udphop":
		var o udphop.Option
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return udphop.New(o)
	case "xdns":
		var o xdns.Option
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return xdns.New(o)
	case "xicmp":
		var o xicmp.Config
		if err := decodeMask(settings, &o); err != nil {
			return nil, err
		}
		return xicmp.New(o)
	case "mkcp-legacy", "salamander", "realm":
		return nil, fmt.Errorf("finalmask: the %s UDP mask is not supported", typ)
	case "fragment", "xmc":
		return nil, fmt.Errorf("finalmask: %s is not a UDP mask", typ)
	default:
		return nil, fmt.Errorf("finalmask: unknown UDP mask %q, want noise, header-custom, sudoku, udphop, xdns or xicmp", typ)
	}
}

// Parse builds the chains; nil when the block is absent or empty.
func (o *Option) Parse() (*finalmask.FinalMask, error) {
	if o == nil || (len(o.TCP) == 0 && len(o.UDP) == 0) {
		return nil, nil
	}
	tcp := make([]finalmask.TCPMask, 0, len(o.TCP))
	for i, entry := range o.TCP {
		mask, err := BuildTCPMask(entry)
		if err != nil {
			return nil, fmt.Errorf("finalmask.tcp[%d]: %w", i, err)
		}
		tcp = append(tcp, mask)
	}
	udp := make([]finalmask.UDPMask, 0, len(o.UDP))
	for i, entry := range o.UDP {
		mask, err := BuildUDPMask(entry)
		if err != nil {
			return nil, fmt.Errorf("finalmask.udp[%d]: %w", i, err)
		}
		udp = append(udp, mask)
	}
	return finalmask.New(tcp, udp)
}
