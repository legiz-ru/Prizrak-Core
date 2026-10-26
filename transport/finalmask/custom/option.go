package custom

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask"
)

// Item is one entry of a sequence as written in the config. Packet is the
// bytes to send or expect: a string (by Type: str, hex, base64) or a list of
// byte values (Type array, the default); exactly one of Packet, Rand, Reuse
// and Transform is set. Capture keeps the bytes under a name, Reuse sends or
// expects a captured one, Transform computes the bytes.
type Item struct {
	Delay     finalmask.Range  `proxy:"delay,omitempty"` // TCP only, milliseconds before the item
	Rand      int32            `proxy:"rand,omitempty"`
	RandRange *finalmask.Range `proxy:"rand-range,omitempty"` // byte values of Rand, 0-255 by default
	Capture   string           `proxy:"capture,omitempty"`
	Type      string           `proxy:"type,omitempty"`
	Reuse     string           `proxy:"reuse,omitempty"`
	Transform *Transform       `proxy:"transform,omitempty"`
	Packet    any              `proxy:"packet,omitempty"`
}

type Transform struct {
	Op   string         `proxy:"op"`
	Args []TransformArg `proxy:"args"`
}

// TransformArg is one argument; exactly one of Bytes (with Type), U64,
// Reuse, Metadata and Transform is set.
type TransformArg struct {
	Type      string     `proxy:"type,omitempty"`
	Bytes     any        `proxy:"bytes,omitempty"`
	U64       *uint64    `proxy:"u64,omitempty"`
	Reuse     string     `proxy:"reuse,omitempty"`
	Metadata  string     `proxy:"metadata,omitempty"`
	Transform *Transform `proxy:"transform,omitempty"`
}

// TCPOption is the "header-custom" TCP mask as written in the config.
type TCPOption struct {
	Clients [][]Item `proxy:"clients,omitempty"`
	Servers [][]Item `proxy:"servers,omitempty"`
	Errors  [][]Item `proxy:"errors,omitempty"`
}

// UDPOption is the "header-custom" UDP mask as written in the config. Mode
// is "prefix" (the default) or "standalone".
type UDPOption struct {
	Mode   string `proxy:"mode,omitempty"`
	Client []Item `proxy:"client,omitempty"`
	Server []Item `proxy:"server,omitempty"`
}

var varNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ParseBytes reads a packet value: a list of byte values, or a string by
// typ: "str" as is, "hex", "base64"; "" and "array" take either.
func ParseBytes(value any, typ string) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	typ = strings.ToLower(strings.TrimSpace(typ))
	if list, ok := value.([]any); ok {
		if typ != "" && typ != "array" {
			return nil, fmt.Errorf("packet of type %s must be a string", typ)
		}
		out := make([]byte, 0, len(list))
		for _, v := range list {
			n, ok := toInt(v)
			if !ok || n < 0 || n > 255 {
				return nil, fmt.Errorf("invalid byte value %v", v)
			}
			out = append(out, byte(n))
		}
		return out, nil
	}
	str, ok := value.(string)
	if !ok {
		if n, isInt := toInt(value); isInt && (typ == "" || typ == "array") {
			if n < 0 || n > 255 {
				return nil, fmt.Errorf("invalid byte value %v", value)
			}
			return []byte{byte(n)}, nil
		}
		return nil, fmt.Errorf("packet must be a string or a list of bytes, got %T", value)
	}
	switch typ {
	case "", "array", "str":
		return []byte(str), nil
	case "hex":
		return hex.DecodeString(strings.TrimPrefix(strings.ReplaceAll(str, " ", ""), "0x"))
	case "base64":
		return base64.StdEncoding.DecodeString(str)
	default:
		return nil, fmt.Errorf("unknown packet type %q", typ)
	}
}

func toInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case int32:
		return int64(n), true
	case uint64:
		return int64(n), true
	case uint:
		return int64(n), true
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	}
	return 0, false
}

func validateVarName(name string) error {
	if name == "" {
		return nil
	}
	if !varNamePattern.MatchString(name) {
		return fmt.Errorf("invalid variable name %q", name)
	}
	return nil
}

func (it *Item) validate() error {
	if err := validateVarName(it.Capture); err != nil {
		return err
	}
	if err := validateVarName(it.Reuse); err != nil {
		return err
	}
	kinds := 0
	if it.Packet != nil {
		kinds++
	}
	if it.Rand > 0 {
		kinds++
	}
	if it.Reuse != "" {
		kinds++
	}
	if it.Transform != nil {
		kinds++
	}
	if kinds > 1 {
		return errors.New("exactly one of packet, rand, reuse and transform must be set")
	}
	if kinds == 0 && it.Capture != "" {
		return errors.New("capture needs packet, rand, reuse or transform")
	}
	return nil
}

func (it *Item) randRange() (int32, int32, error) {
	if it.RandRange == nil {
		return 0, 255, nil
	}
	from, to := it.RandRange.From, it.RandRange.To
	if from > to {
		from, to = to, from
	}
	if from < 0 || to > 255 {
		return 0, 0, fmt.Errorf("invalid rand-range %s", it.RandRange)
	}
	return int32(from), int32(to), nil
}

func (it *Item) buildTCP() (*TCPItem, error) {
	if err := it.validate(); err != nil {
		return nil, err
	}
	randMin, randMax, err := it.randRange()
	if err != nil {
		return nil, err
	}
	packet, err := ParseBytes(it.Packet, it.Type)
	if err != nil {
		return nil, err
	}
	transform, err := it.Transform.build()
	if err != nil {
		return nil, err
	}
	delayMin, delayMax := int64(it.Delay.From), int64(it.Delay.To)
	if delayMin > delayMax {
		delayMin, delayMax = delayMax, delayMin
	}
	return &TCPItem{
		DelayMin: delayMin,
		DelayMax: delayMax,
		Rand:     it.Rand,
		RandMin:  randMin,
		RandMax:  randMax,
		Packet:   packet,
		Save:     it.Capture,
		Var:      it.Reuse,
		Expr:     transform,
	}, nil
}

func (it *Item) buildUDP() (*UDPItem, error) {
	tcp, err := it.buildTCP()
	if err != nil {
		return nil, err
	}
	return &UDPItem{
		Rand:    tcp.Rand,
		RandMin: tcp.RandMin,
		RandMax: tcp.RandMax,
		Packet:  tcp.Packet,
		Save:    tcp.Save,
		Var:     tcp.Var,
		Expr:    tcp.Expr,
	}, nil
}

func (t *Transform) build() (*Expr, error) {
	if t == nil {
		return nil, nil
	}
	if t.Op == "" {
		return nil, errors.New("transform op is required")
	}
	if len(t.Args) == 0 {
		return nil, errors.New("transform args are required")
	}
	args := make([]*ExprArg, 0, len(t.Args))
	for _, arg := range t.Args {
		built, err := arg.build()
		if err != nil {
			return nil, err
		}
		args = append(args, built)
	}
	return &Expr{Op: t.Op, Args: args}, nil
}

func (a TransformArg) build() (*ExprArg, error) {
	kinds := 0
	if a.Bytes != nil {
		kinds++
	}
	if a.U64 != nil {
		kinds++
	}
	if a.Reuse != "" {
		kinds++
	}
	if a.Metadata != "" {
		kinds++
	}
	if a.Transform != nil {
		kinds++
	}
	if kinds != 1 {
		return nil, errors.New("transform arg must set exactly one of bytes, u64, reuse, metadata and transform")
	}
	switch {
	case a.Bytes != nil:
		value, err := ParseBytes(a.Bytes, a.Type)
		if err != nil {
			return nil, err
		}
		if value == nil {
			value = []byte{}
		}
		return &ExprArg{Bytes: value}, nil
	case a.U64 != nil:
		v := *a.U64
		return &ExprArg{U64: &v}, nil
	case a.Reuse != "":
		if err := validateVarName(a.Reuse); err != nil {
			return nil, err
		}
		return &ExprArg{Var: a.Reuse}, nil
	case a.Metadata != "":
		return &ExprArg{Metadata: a.Metadata}, nil
	default:
		expr, err := a.Transform.build()
		if err != nil {
			return nil, err
		}
		return &ExprArg{Expr: expr}, nil
	}
}

func buildSequences(lists [][]Item) ([]*TCPSequence, error) {
	out := make([]*TCPSequence, len(lists))
	for i, list := range lists {
		out[i] = &TCPSequence{}
		for j := range list {
			item, err := list[j].buildTCP()
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", j, err)
			}
			out[i].Sequence = append(out[i].Sequence, item)
		}
	}
	return out, nil
}

func buildUDPItems(list []Item) ([]*UDPItem, error) {
	out := make([]*UDPItem, 0, len(list))
	for j := range list {
		item, err := list[j].buildUDP()
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", j, err)
		}
		out = append(out, item)
	}
	return out, nil
}

// NewTCP builds the TCP mask from its config.
func NewTCP(o TCPOption) (*TCPConfig, error) {
	clients, err := buildSequences(o.Clients)
	if err != nil {
		return nil, fmt.Errorf("header-custom clients: %w", err)
	}
	servers, err := buildSequences(o.Servers)
	if err != nil {
		return nil, fmt.Errorf("header-custom servers: %w", err)
	}
	errs, err := buildSequences(o.Errors)
	if err != nil {
		return nil, fmt.Errorf("header-custom errors: %w", err)
	}
	return &TCPConfig{Clients: clients, Servers: servers, Errors: errs}, nil
}

// NewUDP builds the UDP mask from its config: a *UDPConfig in prefix mode,
// a *UDPStandaloneConfig in standalone mode.
func NewUDP(o UDPOption) (finalmask.UDPMask, error) {
	client, err := buildUDPItems(o.Client)
	if err != nil {
		return nil, fmt.Errorf("header-custom client: %w", err)
	}
	server, err := buildUDPItems(o.Server)
	if err != nil {
		return nil, fmt.Errorf("header-custom server: %w", err)
	}
	switch strings.ToLower(o.Mode) {
	case "", "prefix":
		return &UDPConfig{Client: client, Server: server}, nil
	case "standalone":
		return &UDPStandaloneConfig{Client: client, Server: server}, nil
	default:
		return nil, fmt.Errorf("header-custom: unknown udp mode %q, want prefix or standalone", o.Mode)
	}
}
