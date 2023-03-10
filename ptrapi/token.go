package ptrapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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
		tokenDgst := hex.EncodeToString(tokenSha256[:])

		fmt.Fprintf(os.Stderr, "TOKEN: %s\n", bearerHeader)

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

		tokenSha256 := sha256.Sum256([]byte(opts[1]))
		tokenDgst := hex.EncodeToString(tokenSha256[:])

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

type openSSHDecryptFunc func(CipherName, KdfName, KdfOpts string, PrivKeyBlock []byte) ([]byte, error)

func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

func parseOpenSSHPrivateKey(pemBytes []byte, decrypt openSSHDecryptFunc) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("ssh: no key found")
	}

	if encryptedBlock(block) {
		return "", &ssh.PassphraseMissingError{}
	}

	if block.Type != "OPENSSH PRIVATE KEY" {
		return "", fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	key := block.Bytes

	const magic = "openssh-key-v1\x00"
	if len(key) < len(magic) || string(key[:len(magic)]) != magic {
		return "", errors.New("ssh: invalid openssh private key format")
	}
	remaining := key[len(magic):]

	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}

	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return "", err
	}
	if w.NumKeys != 1 {
		// We only support single key files, and so does OpenSSH.
		// https://github.com/openssh/openssh-portable/blob/4103a3ec7/sshkey.c#L4171
		return "", errors.New("ssh: multi-key files are not supported")
	}

	privKeyBlock, err := decrypt(w.CipherName, w.KdfName, w.KdfOpts, w.PrivKeyBlock)
	if err != nil {
		if err, ok := err.(*ssh.PassphraseMissingError); ok {
			pub, errPub := ssh.ParsePublicKey(w.PubKey)
			if errPub != nil {
				return "", fmt.Errorf("ssh: failed to parse embedded public key: %v", errPub)
			}
			err.PublicKey = pub
		}
		return "", err
	}

	pk1 := struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Rest    []byte `ssh:"rest"`
	}{}

	if err := ssh.Unmarshal(privKeyBlock, &pk1); err != nil || pk1.Check1 != pk1.Check2 {
		if w.CipherName != "none" {
			return "", x509.IncorrectPasswordError
		}
		return "", errors.New("ssh: malformed OpenSSH key")
	}

	switch pk1.Keytype {
	case ssh.KeyAlgoRSA:
		// https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L2760-L2773
		key := struct {
			N       *big.Int
			E       *big.Int
			D       *big.Int
			Iqmp    *big.Int
			P       *big.Int
			Q       *big.Int
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return "", err
		}

		if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
			return "", err
		}

		return key.Comment, nil
	case ssh.KeyAlgoED25519:
		key := struct {
			Pub     []byte
			Priv    []byte
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return "", err
		}

		if len(key.Priv) != ed25519.PrivateKeySize {
			return "", errors.New("ssh: private key unexpected length")
		}

		if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
			return "", err
		}

		return key.Comment, nil
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		key := struct {
			Curve   string
			Pub     []byte
			D       *big.Int
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return "", err
		}

		if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
			return "", err
		}

		switch key.Curve {
		case "nistp256":
		case "nistp384":
		case "nistp521":
		default:
			return "", errors.New("ssh: unhandled elliptic curve: " + key.Curve)
		}

		return key.Comment, nil
	default:
		return "", errors.New("ssh: unhandled key type")
	}
}

func unencryptedOpenSSHKey(cipherName, kdfName, kdfOpts string, privKeyBlock []byte) ([]byte, error) {
	if kdfName != "none" || cipherName != "none" {
		return nil, &ssh.PassphraseMissingError{}
	}
	if kdfOpts != "" {
		return nil, errors.New("ssh: invalid openssh private key")
	}
	return privKeyBlock, nil
}

func checkOpenSSHKeyPadding(pad []byte) error {
	for i, b := range pad {
		if int(b) != i+1 {
			return errors.New("ssh: padding not as expected")
		}
	}
	return nil
}
