package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	auth "github.com/abbot/go-http-auth"
)

var version = "dev"

func main() {
	bindFlag := flag.String("bind", "127.0.0.1:8080", "The address that will be bound.")
	logFlag := flag.Bool("log", false, "Log reqests?")
	corsFlag := flag.Bool("cors", false, "Add CORS headers?")
	gzipFlag := flag.Bool("gzip", false, "GZIP content?")
	authFlag := flag.String("auth", "", "Auth?")
	vFlag := flag.Bool("version", false, "Version")
	flag.Parse()

	if *vFlag {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}

	dir := "."

	args := flag.Args()
	if len(args) > 0 {
		dir = args[0]
	}

	var h http.Handler = http.FileServer(http.Dir(dir))
	if *corsFlag {
		h = CORS(h)
	}
	if *logFlag {
		h = LogRequests(h)
	}
	if *gzipFlag {
		h = GZIP(h)
	}
	if *authFlag != "" {
		authenticator, err := loadAuthenticator(*authFlag)
		if err != nil {
			log.Fatalf("load authenticator: %v", err)
		}
		h = Auth(authenticator, h)
	}

	log.Printf("Serving [%s] at [%s].", dir, *bindFlag)
	log.Fatal(http.ListenAndServe(*bindFlag, h))
}

func Auth(authenticator auth.Authenticator, h http.Handler) http.Handler {
	handle := func(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
		h.ServeHTTP(w, &r.Request)
	}
	return http.HandlerFunc(authenticator(handle))
}

func CORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "GET")
		w.Header().Add("Access-Control-Allow-Headers", "Accept")
		h.ServeHTTP(w, r)
	})
}

func LogRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s from %s took %s\n", r.Method, r.URL, r.RemoteAddr, time.Since(start))
	})
}

func GZIP(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gzr := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		h.ServeHTTP(gzr, r)
	})
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	if "" == w.Header().Get("Content-Type") {
		// If no content type, apply sniffing algorithm to un-gzipped body.
		w.Header().Set("Content-Type", http.DetectContentType(b))
	}
	return w.Writer.Write(b)
}

func loadAuthenticator(urn string) (auth.Authenticator, error) {
	i := strings.IndexRune(urn, '?')
	if i <= 0 {
		return nil, fmt.Errorf("no auth type specified")
	}
	typ := urn[:i]
	rest := urn[i+1:]

	switch typ {
	case "basic":
		params, err := url.ParseQuery(rest)
		if err != nil {
			return nil, err
		}
		realm := params.Get("realm")
		secrets := params.Get("secrets")
		if secrets == "" {
			return nil, fmt.Errorf("no htpasswd file specified")
		}
		sp := auth.HtpasswdFileProvider(secrets)
		a := auth.NewBasicAuthenticator(realm, sp)
		return a.Wrap, nil
	default:
		return nil, fmt.Errorf("unknown auth type specified")
	}
}
