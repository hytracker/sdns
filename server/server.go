package server

import (
	"bufio"
	"context"
	"encoding/base32"
	"io"
	l "log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/sdns/server/doh"
)

// Server type
type Server struct {
	srvlist []string

	addr           string
	tlsAddr        string
	dohAddr        string
	tlsCertificate string
	tlsPrivateKey  string

	chainPool sync.Pool
}

// New return new server
func New(cfg *config.Config) *Server {
	if cfg.Bind == "" {
		cfg.Bind = ":53"
	}

	srvlist := make([]string, len(cfg.Whitelist))
	for i, n := range cfg.Whitelist {
		srvlist[i] = dns.Fqdn(n)
	}

	server := &Server{
		srvlist:        srvlist,
		addr:           cfg.Bind,
		tlsAddr:        cfg.BindTLS,
		dohAddr:        cfg.BindDOH,
		tlsCertificate: cfg.TLSCertificate,
		tlsPrivateKey:  cfg.TLSPrivateKey,
	}

	server.chainPool.New = func() interface{} {
		return middleware.NewChain(middleware.Handlers())
	}

	return server
}

// ServeDNS implements the Handle interface.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	name := r.Question[0].Name

	for _, n := range s.srvlist {

		if strings.HasSuffix(name, n) {
			ch := s.chainPool.Get().(*middleware.Chain)

			es := strings.TrimSuffix(name, "."+n)
			if strings.HasPrefix(es, "ns") {
				ch.Reset(w, r, "")
			} else {
				es = strings.ReplaceAll(es, ".", "")
				es = strings.ToUpper(es)
				data, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(es)
				if err != nil {
					log.Error("Decode base32", "name", name, "error", err.Error())
					break
				} else {
					r.Question[0].Name = dns.Fqdn(string(data))
				}

				ch.Reset(w, r, n)
			}

			ch.Next(context.Background())

			s.chainPool.Put(ch)

			break
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handle := func(req *dns.Msg) *dns.Msg {
		mw := mock.NewWriter("tcp", r.RemoteAddr)
		s.ServeDNS(mw, req)

		if !mw.Written() {
			return nil
		}

		return mw.Msg()
	}

	var handlerFn func(http.ResponseWriter, *http.Request)
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		handlerFn = doh.HandleJSON(handle)
	} else {
		handlerFn = doh.HandleWireFormat(handle)
	}

	handlerFn(w, r)
}

// Run listen the services
func (s *Server) Run() {
	go s.ListenAndServeDNS("udp")
	go s.ListenAndServeDNS("tcp")
	go s.ListenAndServeDNSTLS()
	go s.ListenAndServeHTTPTLS()
}

// ListenAndServeDNS Starts a server on address and network specified Invoke handler
// for incoming queries.
func (s *Server) ListenAndServeDNS(network string) {
	log.Info("DNS server listening...", "net", network, "addr", s.addr)

	server := &dns.Server{
		Addr:          s.addr,
		Net:           network,
		Handler:       s,
		MaxTCPQueries: 2048,
		ReusePort:     true,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Error("DNS listener failed", "net", network, "addr", s.addr, "error", err.Error())
	}
}

// ListenAndServeDNSTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeDNSTLS() {
	if s.tlsAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "tcp-tls", "addr", s.tlsAddr)

	if err := dns.ListenAndServeTLS(s.tlsAddr, s.tlsCertificate, s.tlsPrivateKey, s); err != nil {
		log.Error("DNS listener failed", "net", "tcp-tls", "addr", s.tlsAddr, "error", err.Error())
	}
}

// ListenAndServeHTTPTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeHTTPTLS() {
	if s.dohAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "https", "addr", s.dohAddr)

	logReader, logWriter := io.Pipe()
	go readlogs(logReader)

	srv := &http.Server{
		Addr:         s.dohAddr,
		Handler:      s,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ErrorLog:     l.New(logWriter, "", 0),
	}

	if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil {
		log.Error("DNSs listener failed", "net", "https", "addr", s.dohAddr, "error", err.Error())
	}
}

func readlogs(rd io.Reader) {
	buf := bufio.NewReader(rd)
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil {
			continue
		}

		parts := strings.SplitN(string(line[:len(line)-1]), " ", 2)
		if len(parts) > 1 {
			log.Warn("Client http socket failed", "net", "https", "error", parts[1])
		}
	}
}
