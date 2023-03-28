package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/vpngen/partner-api/embapi"
)

const (
	dataKeyRotationDuration = 10 * 24 * time.Hour // 10 days
	defaultIndexCacheSize   = 100 << 20           // 100 Mb
)

const (
	dbkeyString = "rUqRZtB1TUHtM0wzAIyuzX/RIkg3Yo9L+8evLxOQKC4="
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("cwd: %s\n", err)
	}

	path, err := filepath.Abs(filepath.Join(cwd, "db"))
	if err != nil {
		log.Fatalf("abs path: %s\n", err)
	}

	token1 := [32]byte{}
	if _, err := rand.Reader.Read(token1[:]); err != nil {
		log.Fatalf("gen token1: %s\n", err)
	}

	token2 := [32]byte{}
	if _, err := rand.Reader.Read(token2[:]); err != nil {
		log.Fatalf("gen token1: %s\n", err)
	}

	dbkey := make([]byte, 32)
	if _, err := base64.StdEncoding.WithPadding(base64.StdPadding).Decode(dbkey[:], []byte(dbkeyString)); err != nil {
		log.Fatalf("gen badger key: %s\n", err)
	}

	dbopts := badger.DefaultOptions(path).
		WithIndexCacheSize(defaultIndexCacheSize).
		WithEncryptionKey(dbkey).
		WithEncryptionKeyRotationDuration(dataKeyRotationDuration) // 10 days

	db, err := badger.Open(dbopts)
	if err != nil {
		log.Fatalf("open db: %s\n", err)
	}

	defer db.Close()

	c := 0
	for {
		bool := false

		switch c % 2 {
		case 0:
			bool, err = embapi.CheckRequestLimit(db, token2)
			if err != nil {
				log.Fatalf("loop: %s\n", err)
			}
		default:
			bool, err = embapi.CheckRequestLimit(db, token1)
			if err != nil {
				log.Fatalf("loop: %s\n", err)
			}
		}

		if !bool {
			break
		}

		c++
	}

	fmt.Printf("%d\n", c)
}
