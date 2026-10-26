package outbound

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckFinalMaskNetwork(t *testing.T) {
	udp, err := (&FinalMaskOption{UDP: []map[string]any{{"type": "noise", "noise": []any{map[string]any{"rand": 8}}}}}).Parse()
	require.NoError(t, err)
	tcp, err := (&FinalMaskOption{TCP: []map[string]any{{"type": "fragment", "length": "1"}}}).Parse()
	require.NoError(t, err)

	require.NoError(t, checkFinalMaskNetwork(nil, "vless", "", nil))
	require.NoError(t, checkFinalMaskNetwork(tcp, "trojan", "ws", nil))
	require.NoError(t, checkFinalMaskNetwork(udp, "vless", "xhttp", []string{"h3"}))
	require.Error(t, checkFinalMaskNetwork(udp, "vless", "xhttp", nil))
	require.Error(t, checkFinalMaskNetwork(udp, "vless", "xhttp", []string{"h2", "h3"}))
	require.Error(t, checkFinalMaskNetwork(udp, "vless", "", []string{"h3"}))
	require.Error(t, checkFinalMaskNetwork(udp, "trojan", "grpc", []string{"h3"}))
}
