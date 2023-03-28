package ptrapi

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/dgraph-io/badger/v4"
	oaerrors "github.com/go-openapi/errors"
	"github.com/golang-jwt/jwt"
)

type AuthEntry struct {
	Token      string
	AllowedIPs []netip.Prefix
}

type AuthMap map[string]AuthEntry

var (
	ErrTokenInvalid    = oaerrors.New(401, "invalid token")
	ErrTooManyRequests = oaerrors.New(429, "too many requests")
)

// ValidateBearer - validate our key.
func ValidateBearer(db *badger.DB, secret string, m AuthMap) func(string) (interface{}, error) {
	return func(bearerHeader string) (interface{}, error) {
		_, bearerToken, ok := strings.Cut(bearerHeader, " ")
		if !ok {
			return nil, ErrTokenInvalid
		}

		tokenSha256 := sha256.Sum256([]byte(bearerToken))
		tokenDgst := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(tokenSha256[:])

		a, ok := m[tokenDgst]
		if !ok {
			return nil, ErrTokenInvalid
		}

		fmt.Fprintf(os.Stderr, "a: %+v\n", a)

		ok, err := CheckRequestLimit(db, tokenSha256)
		if err != nil {
			return nil, ErrTokenInvalid
		}

		if !ok {
			return nil, ErrTooManyRequests
		}

		// Parse the signed token
		parsedToken, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Parse: %s secret: %s\n", err, secret)
			return nil, ErrTokenInvalid
		}

		// Check if the token is valid
		_, ok = parsedToken.Claims.(jwt.MapClaims)
		if !ok || !parsedToken.Valid {
			return nil, ErrTokenInvalid
		}

		return a, nil
	}
}

func ReadTokensFile(filename string) (AuthMap, error) {
	m := make(AuthMap)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		if line[0] == '#' {
			continue
		}

		token, prefixes, ok := strings.Cut(line, ",")
		if len(token) == 0 {
			continue
		}

		tokenSha256 := sha256.Sum256([]byte(token))
		tokenDgst := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(tokenSha256[:])

		allowedIPs := []netip.Prefix{}
		if ok {
			for _, prefix := range strings.Split(prefixes, ",") {
				ipnet, err := netip.ParsePrefix(prefix)
				if err != nil {
					ip, err := netip.ParseAddr(prefix)
					if err != nil {
						continue
					}

					allowedIPs = append(allowedIPs, netip.PrefixFrom(ip, 32))

					continue
				}

				allowedIPs = append(allowedIPs, ipnet)
			}
		}

		m[tokenDgst] = AuthEntry{
			Token:      tokenDgst,
			AllowedIPs: allowedIPs,
		}

		fmt.Fprintf(os.Stderr, "tokenDgst: %s\n", tokenDgst)
	}

	return m, nil
}
