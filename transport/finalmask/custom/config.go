// Package custom is the "header-custom" finalmask of Xray-core: a scripted
// exchange of byte sequences at the start of a TCP stream, or a header in
// front of every datagram, with captured values, metadata and transforms.
package custom

// Expr is a transform: op applied to args, see evaluateExpr for the ops.
type Expr struct {
	Op   string
	Args []*ExprArg
}

// ExprArg is one argument of an Expr; exactly one field is set.
type ExprArg struct {
	Bytes    []byte
	U64      *uint64
	Var      string
	Metadata string
	Expr     *Expr
}

// TCPItem is one piece of a TCP sequence; exactly one of Rand, Packet, Var
// and Expr is set, Save keeps the bytes under a name for later items.
type TCPItem struct {
	DelayMin, DelayMax int64 // milliseconds before the item, flushing what came before
	Rand               int32 // this many random bytes in [RandMin, RandMax]
	RandMin, RandMax   int32
	Packet             []byte
	Save               string
	Var                string
	Expr               *Expr
}

type TCPSequence struct {
	Sequence []*TCPItem
}

// TCPConfig alternates Clients[i] (sent by the client) and Servers[i] (sent
// by the server); Errors[i] is what the server answers when Clients[i] does
// not match.
type TCPConfig struct {
	Clients []*TCPSequence
	Servers []*TCPSequence
	Errors  []*TCPSequence
}

type UDPItem struct {
	Rand             int32
	RandMin, RandMax int32
	Packet           []byte
	Save             string
	Var              string
	Expr             *Expr
}

// UDPConfig is the "prefix" mode: Client is put in front of every client
// datagram and Server in front of every server one.
type UDPConfig struct {
	Client []*UDPItem
	Server []*UDPItem
}

// UDPStandaloneConfig is the "standalone" mode: Client and Server are
// exchanged once as datagrams of their own before the first payload.
type UDPStandaloneConfig struct {
	Client []*UDPItem
	Server []*UDPItem
}
