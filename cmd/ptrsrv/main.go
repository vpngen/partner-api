package main

import (
	"context"
	"crypto/tls"
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
	DefaultTokensFile     = "/var/lib/partners-api/tokens.lst"
	DefaultManagementUser = "_alice_"
)

var (
	ErrEmptyAuthUser = goerrors.New("empty user")
)

func main() {
	listeners, addr, pcors, authUser, keysDir, certDir, err := parseArgs()
	if err != nil {
		log.Fatalf("Can't init: %s\n", err)
	}

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

	handler := initSwaggerAPI(pcors, keysDir, authMap, authUser, addr)

	// On signal, gracefully shut down the server and wait 5
	// seconds for current connections to stop.

	done := make(chan struct{})
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	server := &http.Server{
		Handler:     handler,
		IdleTimeout: 60 * time.Minute,
	}

	var serverTLS *http.Server

	if len(listeners) == 2 {
		// openssl req -x509 -nodes -days 10000 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj '/CN=vpn.works/O=VPNGen/C=LT/ST=Vilniaus Apskritis/L=Vilnius' -keyout vpn.works.key -out vpn.works.crt
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
		default:
			fmt.Fprintf(os.Stderr, "Skip TLS: can't open cert/key pair: %s\n", err)
		}
	}

	go func() {
		<-quit

		fmt.Fprintln(os.Stderr, "Quit signal received...")

		wg := sync.WaitGroup{}

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

	// Wait for existing connections before exiting.
	<-done
}

func parseArgs() ([]net.Listener, netip.AddrPort, bool, string, string, string, error) {
	var (
		keydir, certdir string
		addrPort        netip.AddrPort
		err             error
	)

	keyDir := flag.String("k", DefaultSSHKeysDir, "Dir for ssh keysfiles.")
	certDir := flag.String("e", DefaultCertDir, "Dir for TLS certificate and key.")
	authUser := flag.String("u", DefaultManagementUser, "")

	listenAddr := flag.String("l", "", "Listen addr:port (http and https separate with commas)")
	pcors := flag.Bool("cors", false, "Turn on permessive CORS (for test)")

	addr := flag.String("a", "", "API management address:port")

	flag.Parse()

	keydir, err = filepath.Abs(*keyDir)
	if err != nil {
		return nil, addrPort, false, "", "", "", fmt.Errorf("keydir: %w", err)
	}

	certdir, err = filepath.Abs(*certDir)
	if err != nil {
		return nil, addrPort, false, "", "", "", fmt.Errorf("certdir: %w", err)
	}

	if *authUser == "" {
		return nil, addrPort, false, "", "", "", fmt.Errorf("user: %w", ErrEmptyAuthUser)
	}

	if *addr != "-" {
		addrPort, err = netip.ParseAddrPort(*addr)
		if err != nil {
			return nil, addrPort, false, "", "", "", fmt.Errorf("ministry addr: %w", err)
		}
	}

	var listeners []net.Listener

	for _, laddr := range strings.Split(*listenAddr, ",") {
		l, err := net.Listen("tcp", laddr)
		if err != nil {
			return nil, addrPort, false, "", "", "", fmt.Errorf("cannot listen: %w", err)
		}

		listeners = append(listeners, l)
	}

	if len(listeners) != 1 && len(listeners) != 2 {
		return nil, addrPort, false, "", "", "", fmt.Errorf("unexpected number of litening (%d != 1|2)",
			len(listeners))
	}

	return listeners, addrPort, *pcors, *authUser, keydir, certdir, nil
}

func initSwaggerAPI(
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

	api.BearerAuth = ptrapi.ValidateBearer(authMap)
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
