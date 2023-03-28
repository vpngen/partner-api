package embapi

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	SSHTimeOut = time.Duration(5 * time.Second)
)

func CreateSSHConfig(filename, username string) (*ssh.ClientConfig, error) {
	// var hostKey ssh.PublicKey

	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         SSHTimeOut,
	}

	return config, nil
}
