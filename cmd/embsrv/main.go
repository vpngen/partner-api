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
	"github.com/vpngen/partner-api/embapi"
	"github.com/vpngen/partner-api/gen/restapi"
	"github.com/vpngen/partner-api/gen/restapi/operations"
	"golang.org/x/crypto/ssh"

	"github.com/gorilla/mux"
)

//go:generate swagger generate server -t ../../gen -f ../../swagger/swagger.yml --exclude-main -A admin

const (
	TLSCertFilename = "fullchain.crt"
	TLSKeyFilename  = "private.key"
)

const (
	DefaultCertDir        = "/etc/embassy-api"
	DefaultSSHKey         = "/etc/embassy-api/id_ed25519"
	DefaultTokensFile     = "/etc/embassy-api/tokens.lst"
	DefaultSessionDbDir   = "/var/lib/embassy-api/db"
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

	jwtSeceret := os.Getenv("JWT_SIGN_KEY")
	if jwtSeceret == "" && len(jwtSeceret) < 32 {
		log.Fatalf("JWT_SIGN_KEY is empty or too short: %s\n", jwtSeceret)
	}

	listeners, addr, pcors, zabbixAddr, authUser, dbDir, tokens, sshKey, certDir, err := parseArgs()
	if err != nil {
		log.Fatalf("Can't init: %s\n", err)
	}

	fmt.Fprintf(os.Stderr, "Database Dir: %s\n", dbDir)
	fmt.Fprintf(os.Stderr, "SSH Private Key: %s\n", sshKey)
	fmt.Fprintf(os.Stderr, "Cert Dir: %s\n", certDir)
	fmt.Fprintf(os.Stderr, "Permessive CORS: %t\n", pcors)

	switch {
	case addr.IsValid() && !addr.Addr().IsUnspecified():
		fmt.Fprintf(os.Stderr, "Ministry address:port: %s\n", addr)
	default:
		fmt.Fprintln(os.Stderr, "Ministry address:port is for DEBUG")
	}

	sshConfig, err := embapi.CreateSSHConfig(sshKey, authUser)
	if err != nil {
		log.Fatalf("Can't find key: %s\n", err)
	}

	authMap, err := embapi.ReadTokensFile(tokens, jwtSeceret)
	if err != nil {
		log.Fatalf("Can't read tokens file: %s\n", err)
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

	handler := initSwaggerAPI(db, pcors, jwtSeceret, authMap, sshConfig, addr)

	var server, serverTLS, serverZabbix *http.Server

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

	if zabbixAddr.IsValid() {
		router := mux.NewRouter()

		router.HandleFunc("/metrics/embassy_integration_token", func(w http.ResponseWriter, r *http.Request) {
			embapi.ZabbixCounterHandler(w, r, authMap)
		})

		serverZabbix = &http.Server{
			Handler:     router,
			IdleTimeout: 60 * time.Minute,
		}
	}

	stop := make(chan struct{})
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go badgerGC(wg, db, authMap, stop)

	fmt.Fprintf(os.Stderr, "Listen HTTP: %s\n", listeners[0].Addr().String())
	if serverTLS != nil {
		fmt.Fprintf(os.Stderr, "Listen HTTPS: %s\n", listeners[1].Addr().String())
	}

	if serverZabbix != nil {
		fmt.Fprintf(os.Stderr, "Listen Zabbix: %s\n", zabbixAddr.String())
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

	if serverZabbix != nil {
		go func() {
			zlistener, err := net.Listen("tcp", zabbixAddr.String())
			if err != nil {
				log.Fatalf("Can't listen Zabbix: %s\n", err)
			}

			if err := serverZabbix.Serve(zlistener); err != nil && !goerrors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Can't serve Zabbix: %s\n", err)
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

		if serverZabbix != nil {
			fmt.Fprintln(os.Stderr, "Server Zabbix is shutting down")
			wg.Add(1)
			go closeFunc(serverZabbix)
		}

		wg.Wait()

		close(done)
	}()

	// Wait for existing connections before exiting.
	<-done
}

func parseArgs() ([]net.Listener, netip.AddrPort, bool, netip.AddrPort, string, string, string, string, string, error) {
	var (
		dbdir, sshkey, tokens, certdir string
		addrPort, zabbix               netip.AddrPort
		err                            error
	)

	sshKey := flag.String("k", DefaultSSHKey, "SSH private key.")
	tokensFile := flag.String("t", DefaultTokensFile, "Valid tokens file.")
	certDir := flag.String("e", DefaultCertDir, "Dir for TLS certificate and key.")
	dbDir := flag.String("d", DefaultSessionDbDir, "Dir for session db.")
	authUser := flag.String("u", DefaultManagementUser, "")

	listenAddr := flag.String("l", "", "Listen addr:port (http[,https] separate with commas)")
	zabbixAddr := flag.String("z", "", "Listen addr:port for zabbix metrics")
	pcors := flag.Bool("cors", false, "Turn on permessive CORS (for test)")

	addr := flag.String("a", "", "API management address:port")

	flag.Parse()

	dbdir, err = filepath.Abs(*dbDir)
	if err != nil {
		return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("dbdir: %w", err)
	}

	sshkey, err = filepath.Abs(*sshKey)
	if err != nil {
		return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("sshkey: %w", err)
	}

	tokens, err = filepath.Abs(*tokensFile)
	if err != nil {
		return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("tokens: %w", err)
	}

	certdir, err = filepath.Abs(*certDir)
	if err != nil {
		return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("certdir: %w", err)
	}

	if *authUser == "" {
		return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("user: %w", ErrEmptyAuthUser)
	}

	if *addr != "-" {
		addrPort, err = netip.ParseAddrPort(*addr)
		if err != nil {
			return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("ministry addr: %w", err)
		}
	}

	var listeners []net.Listener

	for _, laddr := range strings.Split(*listenAddr, ",") {
		l, err := net.Listen("tcp", laddr)
		if err != nil {
			return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("cannot listen: %w", err)
		}

		listeners = append(listeners, l)
	}

	if len(listeners) != 1 && len(listeners) != 2 {
		return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("unexpected number of litening (%d != 1|2)",
			len(listeners))
	}

	if *zabbixAddr != "" {
		zabbix, err = netip.ParseAddrPort(*zabbixAddr)
		if err != nil {
			return nil, addrPort, false, zabbix, "", "", "", "", "", fmt.Errorf("zabbix addr: %w", err)
		}
	}

	return listeners, addrPort, *pcors, zabbix, *authUser, dbdir, tokens, sshkey, certdir, nil
}

func initSwaggerAPI(
	db *badger.DB,
	pcors bool,
	jwtSeceret string,
	authMap embapi.AuthMap,
	sshConfig *ssh.ClientConfig,
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

	api.BearerAuth = embapi.ValidateBearer(db, jwtSeceret, authMap)
	api.PostAdminHandler = operations.PostAdminHandlerFunc(func(params operations.PostAdminParams, principal interface{}) middleware.Responder {
		return embapi.AddAdmin(params, principal, sshConfig, addr)
	})

	api.PostV2AdminHandler = operations.PostV2AdminHandlerFunc(func(params operations.PostV2AdminParams, principal interface{}) middleware.Responder {
		return embapi.AddAdminV2(params, principal, sshConfig, addr)
	})

	api.PostLongpingHandler = operations.PostLongpingHandlerFunc(func(params operations.PostLongpingParams) middleware.Responder {
		return embapi.Longping(params)
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

func badgerGC(wg *sync.WaitGroup, db *badger.DB, m embapi.AuthMap, stop <-chan struct{}) {
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

			embapi.CountRequests(db, m)

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
