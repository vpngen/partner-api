package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	goerrors "errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/rs/cors"
	"github.com/vpngen/partner-api/gen/restapi"
	"github.com/vpngen/partner-api/gen/restapi/operations"

	"github.com/vpngen/partner-api/ptrapi"
)

//go:generate swagger generate server -t ../../gen -f ../../swagger/swagger.yml --exclude-main -A admin

const (
	TLSCertFilename = "fullchain.crt"
	TLSKeyFilename  = "private.key"
)

const (
	DefaultCertDir        = "/etc/vgcerts"
	DefaultSSHKeysDir     = "/var/lib/partners-api/keys"
	DefaultSessionDbDir   = "/var/lib/partners-api/db"
	DefaultManagementUser = "_alice_"
)

const (
	dataKeyRotationDuration = 10 * 24 * time.Hour // 10 days
	defaultIndexCacheSize   = 10 << 20            // 10 Mb
)

var ErrEmptyAuthUser = goerrors.New("empty user")

func main() {
	dbkeyString := os.Getenv("BADGER_ENC_KEY")
	if dbkeyString == "" {
		log.Fatalf("It is not a base64 encoded key: %s\n", dbkeyString)
	}

	dbkey := make([]byte, 32)
	if _, err := base64.StdEncoding.Decode(dbkey[:], []byte(dbkeyString)); err != nil {
		log.Fatalf("gen badger key: %s\n", err)
	}

	if len(dbkey) != 16 && len(dbkey) != 24 && len(dbkey) != 32 {
		log.Fatalf("It is not a valid key: %s\n", dbkeyString)
	}

	listeners, addr, pcors, authUser, dbDir, keysDir, certDir, err := parseArgs()
	if err != nil {
		log.Fatalf("Can't init: %s\n", err)
	}

	fmt.Fprintf(os.Stderr, "Database Dir: %s\n", dbDir)
	fmt.Fprintf(os.Stderr, "SSH Keys Dir: %s\n", keysDir)
	fmt.Fprintf(os.Stderr, "Cert Dir: %s\n", certDir)
	fmt.Fprintf(os.Stderr, "Permessive CORS: %t\n", pcors)

	switch {
	case addr.IsValid() && !addr.Addr().IsUnspecified():
		fmt.Fprintf(os.Stderr, "Ministry address:port: %s\n", addr)
	default:
		fmt.Fprintln(os.Stderr, "Ministry address:port is for DEBUG")
	}

	authMap, err := ptrapi.ReadKeysDir(keysDir, "vasya")
	if err != nil {
		log.Fatalf("Can't find keys: %s\n", err)
	}

	if len(authMap) == 0 {
		log.Fatalln("Can't find keys")
	}

	dbopts := badger.DefaultOptions(dbDir).
		WithIndexCacheSize(defaultIndexCacheSize).
		WithEncryptionKey(dbkey).
		WithEncryptionKeyRotationDuration(dataKeyRotationDuration) // 10 days

	db, err := badger.Open(dbopts)
	if err != nil {
		log.Fatalf("open db: %s\n", err)
	}

	defer db.Close()

	handler := initSwaggerAPI(db, pcors, keysDir, authMap, authUser, addr)

	var server, serverTLS *http.Server

	switch len(listeners) {
	case 2:
		// openssl req -x509 -nodes -days 10000 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj '/CN=api.vpngen.org/O=VPNGen/C=LT/ST=Vilniaus Apskritis/L=Vilnius' -keyout private.key -out fullchain.crt
		switch cert, err := tls.LoadX509KeyPair(
			filepath.Join(certDir, TLSCertFilename),
			filepath.Join(certDir, TLSKeyFilename),
		); err {
		case nil:
			serverTLS = &http.Server{
				TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
				Handler:     handler,
				IdleTimeout: 60 * time.Minute,
			}

			server = &http.Server{
				Handler:     http.HandlerFunc(httpsRedirectHandler),
				IdleTimeout: 60 * time.Minute,
			}
		default:
			fmt.Fprintf(os.Stderr, "Skip TLS: can't open cert/key pair: %s\n", err)
		}
	}

	if server == nil {
		server = &http.Server{
			Handler:     handler,
			IdleTimeout: 60 * time.Minute,
		}
	}

	stop := make(chan struct{})
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go badgerGC(wg, db, stop)

	fmt.Fprintf(os.Stderr, "Listen HTTP: %s\n", listeners[0].Addr().String())
	if serverTLS != nil {
		fmt.Fprintf(os.Stderr, "Listen HTTPS: %s\n", listeners[1].Addr().String())
	}

	// Start accepting connections.
	go func() {
		if err := server.Serve(listeners[0]); err != nil && !goerrors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Can't serve: %s\n", err)
		}
	}()

	if serverTLS != nil && len(listeners) == 2 {
		// Start accepting connections.
		go func() {
			if err := serverTLS.ServeTLS(listeners[1], "", ""); err != nil && !goerrors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Can't serve TLS: %s\n", err)
			}
		}()
	}

	// On signal, gracefully shut down the server and wait 5
	// seconds for current connections to stop.

	done := make(chan struct{})
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit

		fmt.Fprintln(os.Stderr, "Quit signal received...")

		close(stop)

		closeFunc := func(srv *http.Server) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			srv.SetKeepAlivesEnabled(false)
			if err := srv.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Can't gracefully shut down the server: %s\n", err)
			}
		}

		fmt.Fprintln(os.Stderr, "Server is shutting down")
		wg.Add(1)
		go closeFunc(server)

		if serverTLS != nil {
			fmt.Fprintln(os.Stderr, "Server TLS is shutting down")
			wg.Add(1)
			go closeFunc(serverTLS)
		}

		wg.Wait()

		close(done)
	}()

	// Wait for existing connections before exiting.
	<-done
}

func parseArgs() ([]net.Listener, netip.AddrPort, bool, string, string, string, string, error) {
	var (
		dbdir, keydir, certdir string
		addrPort               netip.AddrPort
		err                    error
	)

	keyDir := flag.String("k", DefaultSSHKeysDir, "Dir for ssh keysfiles.")
	certDir := flag.String("e", DefaultCertDir, "Dir for TLS certificate and key.")
	dbDir := flag.String("d", DefaultSessionDbDir, "Dir for session db.")
	authUser := flag.String("u", DefaultManagementUser, "")

	listenAddr := flag.String("l", "", "Listen addr:port (http[,https] separate with commas)")
	pcors := flag.Bool("cors", false, "Turn on permessive CORS (for test)")

	addr := flag.String("a", "", "API management address:port")

	flag.Parse()

	dbdir, err = filepath.Abs(*dbDir)
	if err != nil {
		return nil, addrPort, false, "", "", "", "", fmt.Errorf("dbdir: %w", err)
	}

	keydir, err = filepath.Abs(*keyDir)
	if err != nil {
		return nil, addrPort, false, "", "", "", "", fmt.Errorf("keydir: %w", err)
	}

	certdir, err = filepath.Abs(*certDir)
	if err != nil {
		return nil, addrPort, false, "", "", "", "", fmt.Errorf("certdir: %w", err)
	}

	if *authUser == "" {
		return nil, addrPort, false, "", "", "", "", fmt.Errorf("user: %w", ErrEmptyAuthUser)
	}

	if *addr != "-" {
		addrPort, err = netip.ParseAddrPort(*addr)
		if err != nil {
			return nil, addrPort, false, "", "", "", "", fmt.Errorf("ministry addr: %w", err)
		}
	}

	var listeners []net.Listener

	for _, laddr := range strings.Split(*listenAddr, ",") {
		l, err := net.Listen("tcp", laddr)
		if err != nil {
			return nil, addrPort, false, "", "", "", "", fmt.Errorf("cannot listen: %w", err)
		}

		listeners = append(listeners, l)
	}

	if len(listeners) != 1 && len(listeners) != 2 {
		return nil, addrPort, false, "", "", "", "", fmt.Errorf("unexpected number of litening (%d != 1|2)",
			len(listeners))
	}

	return listeners, addrPort, *pcors, *authUser, dbdir, keydir, certdir, nil
}

func initSwaggerAPI(
	db *badger.DB,
	pcors bool,
	keysDir string,
	authMap ptrapi.AuthMap,
	authUser string,
	addr netip.AddrPort,
) http.Handler {
	// load embedded swagger file
	swaggerSpec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	if err != nil {
		log.Fatalln(err)
	}

	// create new service API
	api := operations.NewAdminAPI(swaggerSpec)

	api.ServeError = errors.ServeError

	api.UseSwaggerUI()

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	api.BearerAuth = ptrapi.ValidateBearer(db, authMap)
	api.PostAdminHandler = operations.PostAdminHandlerFunc(func(params operations.PostAdminParams, principal interface{}) middleware.Responder {
		return ptrapi.AddAdmin(params, principal, addr)
	})

	switch pcors {
	case true:
		return cors.AllowAll().Handler(
			uiMiddleware(api.Serve(nil)),
		)
	default:
		return uiMiddleware(api.Serve(nil))
	}
}

func uiMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(os.Stderr, "Connect From: %s\n", r.RemoteAddr)

		handler.ServeHTTP(w, r)
	})
}

func badgerGC(wg *sync.WaitGroup, db *badger.DB, stop <-chan struct{}) {
	defer wg.Done()

	timer := time.NewTimer(5 * time.Minute)

	defer timer.Stop()

	for {
		select {
		case <-timer.C:
		again:
			err := db.RunValueLogGC(0.5)
			if err == nil {
				goto again
			}

			timer.Reset(5 * time.Minute)
		case <-stop:
			return
		}
	}
}

func httpsRedirectHandler(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
