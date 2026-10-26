// Package xmc is the "xmc" finalmask of Xray-core: the TCP stream looks like
// a Minecraft client logging in to a server and then playing. The login is
// authenticated with a password-derived RSA key and a signed profile that
// both sides know.
package xmc

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"regexp"

	"github.com/metacubex/mihomo/transport/finalmask"

	"github.com/gofrs/uuid/v5"
)

// Profile is one Minecraft account the client may log in as; the server
// must know the same signed profile.
type Profile struct {
	Username          string
	UUID              []byte
	TexturesValue     string
	TexturesSignature string
}

// Config is the built mask.
type Config struct {
	Password      string
	RSAPrivateKey []byte // PKCS#1 DER, servers only
	RSAPublicKey  []byte // PKIX DER
	Hostname      string
	Profiles      []*Profile
}

// Option is the mask's settings as written in the config.
type Option struct {
	Password string          `proxy:"password"`
	Hostname string          `proxy:"hostname,omitempty"` // the server address of the handshake packet
	Profiles []ProfileOption `proxy:"profiles"`
}

// ProfileOption is a Minecraft profile: resolve the UUID by username at
// https://api.mojang.com/users/profiles/minecraft/{username}, then take the
// signed textures property from
// https://sessionserver.mojang.com/session/minecraft/profile/{uuid}?unsigned=false.
type ProfileOption struct {
	Username          string `proxy:"username"`
	UUID              string `proxy:"uuid"`
	TexturesValue     string `proxy:"textures-value"`
	TexturesSignature string `proxy:"textures-signature"`
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)

func (p ProfileOption) build() (*Profile, error) {
	if !usernamePattern.MatchString(p.Username) {
		return nil, fmt.Errorf("invalid minecraft profile username: %q", p.Username)
	}
	id, err := uuid.FromString(p.UUID)
	if err != nil {
		return nil, fmt.Errorf("invalid minecraft profile UUID: %w", err)
	}
	if p.TexturesValue == "" || p.TexturesSignature == "" {
		return nil, errors.New("incomplete minecraft profile textures")
	}
	return &Profile{
		Username:          p.Username,
		UUID:              id.Bytes(),
		TexturesValue:     p.TexturesValue,
		TexturesSignature: p.TexturesSignature,
	}, nil
}

// New derives the RSA key from the password and checks the profiles.
func New(o Option) (*Config, error) {
	if len(o.Profiles) == 0 {
		return nil, errors.New("xmc: minecraft profiles are required")
	}
	if o.Password == "" {
		return nil, errors.New("xmc: empty password")
	}
	key, err := DeriveRSAKey(o.Password)
	if err != nil {
		return nil, fmt.Errorf("xmc: derive rsa key: %w", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("xmc: marshal rsa public key: %w", err)
	}
	profiles := make([]*Profile, 0, len(o.Profiles))
	for i, p := range o.Profiles {
		profile, err := p.build()
		if err != nil {
			return nil, fmt.Errorf("xmc: profile %d: %w", i, err)
		}
		profiles = append(profiles, profile)
	}
	c := &Config{
		Password:      o.Password,
		Hostname:      o.Hostname,
		RSAPrivateKey: x509.MarshalPKCS1PrivateKey(key),
		RSAPublicKey:  publicKey,
		Profiles:      profiles,
	}
	if _, err := profilesFromConfig(c.Profiles); err != nil {
		return nil, fmt.Errorf("xmc: %w", err)
	}
	return c, nil
}

func (c *Config) WrapConnClient(_ context.Context, conn net.Conn, _ *finalmask.Destination, _ *finalmask.Dialer) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("xmc: %w", err)
	}
	cc, err := newClientConn(conn, profiles, c.Password, c.RSAPublicKey, c.Hostname)
	if err != nil {
		return nil, fmt.Errorf("xmc: %w", err)
	}
	return cc, nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("xmc: %w", err)
	}
	cc, err := wrapConnServer(conn, profiles, c.Password, c.RSAPrivateKey, c.RSAPublicKey)
	if err != nil {
		return nil, fmt.Errorf("xmc: %w", err)
	}
	return cc, nil
}
