package ptrapi

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const fourDecimals = (1 << 15) - 1

const (
	reqCounterPrefix = "reqc"
	reqLimitDuration = time.Hour
	reqLimitNumber   = 60
)

var reqCounterValue = []byte{42}

func CheckReqLimit(dbase *badger.DB, token [32]byte) (bool, error) {
	count := 0
	prefix := append([]byte(reqCounterPrefix), token[:]...)

	if err := dbase.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(badger.DefaultIteratorOptions)

		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			fmt.Fprintf(os.Stderr, "key=%s\n", k)
			count++
		}

		return nil
	}); err != nil {
		return false, fmt.Errorf("count: %w", err)
	}

	if count > reqLimitNumber {
		return false, nil
	}

	if err := incReqCounter(dbase, prefix); err != nil {
		return false, fmt.Errorf("inc: %w", err)
	}

	return true, nil
}

func incReqCounter(dbase *badger.DB, prefix []byte) error {
	key := prefixKey(prefix)

	if err := dbase.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(key, reqCounterValue).WithTTL(reqLimitDuration)
		if err := txn.SetEntry(e); err != nil {
			return fmt.Errorf("set: %w", err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}

func prefixKey(prefix []byte) []byte {
	var suffix = []byte{}

	ts := time.Now().UTC()
	h, m, s, n, j := ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond(), rand.Int()

	fmt.Appendf(suffix, "%02d%02m%02d%04d%04d", h, m, s, n&fourDecimals, j&fourDecimals)

	return append(prefix, suffix...)
}
