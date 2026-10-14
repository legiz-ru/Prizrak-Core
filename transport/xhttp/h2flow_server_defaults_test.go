//go:build go1.24

package xhttp

// Defaults of a governed server in Xray-core-fork (h2flow_transport.go there).
// Prizrak-Core only runs the client role; the governor's tests of a client
// against such a server use them. Upstream keeps them in h2flow_mihomo.go,
// which Prizrak-Core replaces with h2flow_options.go.
const (
	flowServerReceiveWindow = 6 << 20
	flowServerSendWindow    = 4 << 20
)
