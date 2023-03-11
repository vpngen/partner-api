package ptrapi

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	oaerrors "github.com/go-openapi/errors"
)

const (
	sshTimeOut = time.Duration(5 * time.Second)
	optsLen    = 3
)

type AuthEntry struct {
	SSHConfig   *ssh.ClientConfig
	TokenDigest string
	AllowedFrom []netip.Prefix
}

type AuthMap map[string]AuthEntry

var ErrTokenInvalid = oaerrors.New(401, "invalid token")

// ValidateBearer - validate our key.
func ValidateBearer(m AuthMap) func(string) (interface{}, error) {
	return func(bearerHeader string) (interface{}, error) {
		_, bearerToken, ok := strings.Cut(bearerHeader, " ")
		if !ok {
			return nil, ErrTokenInvalid
		}

		tokenSha256 := sha256.Sum256([]byte(bearerToken))
		tokenDgst := base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(tokenSha256[:])

		fmt.Fprintf(os.Stderr, "TOKEN: %s\n", bearerToken)

		if a, ok := m[tokenDgst]; ok {
			return a, nil
		}

		return nil, ErrTokenInvalid
	}
}

func ReadKeysDir(keysDir, username string) (AuthMap, error) {
	keysFiles, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("readdir: %w", err)
	}

	m := make(AuthMap)

	for _, keyFile := range keysFiles {
		if !keyFile.Type().IsRegular() || strings.HasSuffix(keyFile.Name(), ".pub") {
			continue
		}

		conf, comment, err := createSSHConfig(filepath.Join(keysDir, keyFile.Name()), username)
		if err != nil {
			continue
		}

		opts := strings.Split(comment, ";")
		if len(opts) != optsLen {
			continue
		}

		tokenDgst := opts[1]

		list := strings.Split(opts[2], ",")
		acl := []netip.Prefix{}

		for _, item := range list {
			prefix, err := netip.ParsePrefix(item)
			if err != nil {
				addr, err := netip.ParseAddr(item)
				if err != nil {
					return nil, fmt.Errorf("parse acl: %w", err)
				}

				prefix = netip.PrefixFrom(addr, 32)
			}

			acl = append(acl, prefix)
		}

		m[tokenDgst] = AuthEntry{
			SSHConfig:   conf,
			TokenDigest: tokenDgst,
			AllowedFrom: acl,
		}

		fmt.Fprintf(os.Stderr, "File: %s\nToken: %s\nACL: %s\n", keyFile.Name(), tokenDgst, opts[2])
	}

	return m, nil
}

func createSSHConfig(filename, username string) (*ssh.ClientConfig, string, error) {
	// var hostKey ssh.PublicKey

	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, "", fmt.Errorf("read private key: %w", err)
	}

	comment, err := parseOpenSSHPrivateKey(pemBytes, unencryptedOpenSSHKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse comment: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         sshTimeOut,
	}

	return config, comment, nil
}
