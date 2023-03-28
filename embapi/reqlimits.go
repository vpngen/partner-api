package embapi

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const (
	requestCounterPrefix = "req:"
	requestLimitDuration = time.Hour
	requestLimitNumber   = 60
)

var requestCounterValue = []byte{42}

func CheckRequestLimit(db *badger.DB, token [32]byte) (bool, int, error) {
	prefix := append([]byte(requestCounterPrefix), token[:]...)

	count, err := countRequests(db, prefix)
	if err != nil {
		return false, 0, fmt.Errorf("count: %w", err)
	}

	if count > requestLimitNumber {
		return false, count, nil
	}

	if err := incrementRequestCounter(db, prefix); err != nil {
		return false, 0, fmt.Errorf("inc: %w", err)
	}

	return true, count, nil
}

func countRequests(db *badger.DB, prefix []byte) (int, error) {
	count := 0

	if err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(badger.DefaultIteratorOptions)

		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			count++
		}

		return nil
	}); err != nil {
		return 0, fmt.Errorf("prefix seek: %w", err)
	}

	return count, nil
}

func incrementRequestCounter(db *badger.DB, prefix []byte) error {
	key := getRequestCounterKey(prefix)

	if err := db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(key, requestCounterValue).WithTTL(requestLimitDuration)
		if err := txn.SetEntry(e); err != nil {
			return fmt.Errorf("set: %w", err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}

func getRequestCounterKey(prefix []byte) []byte {
	suffix := make([]byte, len(prefix), len(prefix)+16)
	copy(suffix, prefix)
	suffix = append(suffix, ':')

	timestamp := time.Now().UTC().Format("150405.0000")
	suffix = append(suffix, timestamp...)
	suffix = binary.BigEndian.AppendUint32(suffix, uint32(rand.Int31()))

	return suffix
}
