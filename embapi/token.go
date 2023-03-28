package embapi

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
	TokenDgst       string
	TokenName       string
	AllowedIPs      []netip.Prefix
	HourRequsetsNum int
}

type AuthMap map[string]*AuthEntry

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

		ok, count, err := CheckRequestLimit(db, tokenSha256)
		if err != nil {
			return nil, ErrTokenInvalid
		}

		a.HourRequsetsNum = count

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

func ReadTokensFile(filename, secret string) (AuthMap, error) {
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

		token, prefixes, _ := strings.Cut(line, ",")
		if len(token) == 0 {
			continue
		}

		// Parse the signed token
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Parse: %s secret: %s\n", err, secret)
			return nil, ErrTokenInvalid
		}

		// Check if the token is valid
		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok || !parsedToken.Valid {
			return nil, ErrTokenInvalid
		}

		tokenName, ok := claims["name"].(string)
		if !ok || tokenName == "" {
			return nil, ErrTokenInvalid
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

		m[tokenDgst] = &AuthEntry{
			TokenDgst:  tokenDgst,
			AllowedIPs: allowedIPs,
			TokenName:  tokenName,
		}
	}

	return m, nil
}

func CountRequests(db *badger.DB, authMap AuthMap) error {
	for _, a := range authMap {
		tokenSha256 := make([]byte, base64.URLEncoding.WithPadding(base64.NoPadding).DecodedLen(len(a.TokenDgst)))
		_, err := base64.URLEncoding.WithPadding(base64.NoPadding).Decode(tokenSha256, []byte(a.TokenDgst))
		if err != nil {
			return err
		}

		prefix := append([]byte(requestCounterPrefix), tokenSha256...)
		count, err := countRequests(db, prefix)
		if err != nil {
			return fmt.Errorf("count: %w", err)
		}

		a.HourRequsetsNum = count
	}

	return nil
}
