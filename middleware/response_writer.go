package middleware

import (
	"encoding/base32"
	"errors"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// ResponseWriter implement of dns.ResponseWriter
type ResponseWriter interface {
	dns.ResponseWriter
	Msg() *dns.Msg
	Rcode() int
	Written() bool
	Reset(dns.ResponseWriter, string)
	Proto() string
	RemoteIP() net.IP
	Internal() bool
}

type responseWriter struct {
	dns.ResponseWriter
	msg      *dns.Msg
	size     int
	rcode    int
	proto    string
	remoteip net.IP
	internal bool
}

type responseWriterWrapper struct {
	responseWriter

	encodingDomain string
}

var _ ResponseWriter = &responseWriter{}
var errAlreadyWritten = errors.New("msg already written")

func (w *responseWriter) Msg() *dns.Msg {
	return w.msg
}

func (w *responseWriter) Reset(writer dns.ResponseWriter, _ string) {
	w.ResponseWriter = writer
	w.size = -1
	w.msg = nil
	w.rcode = dns.RcodeSuccess

	switch writer.LocalAddr().(type) {
	case (*net.TCPAddr):
		w.proto = "tcp"
		w.remoteip = w.RemoteAddr().(*net.TCPAddr).IP
	case (*net.UDPAddr):
		w.proto = "udp"
		w.remoteip = w.RemoteAddr().(*net.UDPAddr).IP
	}

	w.internal = w.remoteip.IsLoopback()
}

func (w *responseWriter) RemoteIP() net.IP {
	return w.remoteip
}

func (w *responseWriter) Proto() string {
	return w.proto
}

func (w *responseWriter) Rcode() int {
	return w.rcode
}

func (w *responseWriter) Written() bool {
	return w.size != -1
}

func (w *responseWriter) Write(m []byte) (int, error) {
	if w.Written() {
		return 0, errAlreadyWritten
	}

	w.msg = new(dns.Msg)
	err := w.msg.Unpack(m)
	if err != nil {
		return 0, err
	}
	w.rcode = w.msg.Rcode

	n, err := w.ResponseWriter.Write(m)
	w.size = n
	return n, err
}

func (w *responseWriter) WriteMsg(m *dns.Msg) error {
	if w.Written() {
		return errAlreadyWritten
	}

	w.msg = m
	w.rcode = m.Rcode
	w.size = 0

	return w.ResponseWriter.WriteMsg(m)
}

// Internal func
func (w *responseWriter) Internal() bool { return w.internal }

func (w *responseWriterWrapper) WriteMsg(mm *dns.Msg) error {
	m := mm.Copy()
	if w.encodingDomain != "" {
		w.encode_questions(m.Question)
		w.encode_rrs(m.Answer)
		w.encode_rrs(m.Ns)
		w.encode_rrs(m.Extra)
	}

	return w.responseWriter.WriteMsg(m)
}

func (w *responseWriterWrapper) Reset(writer dns.ResponseWriter, ed string) {
	w.encodingDomain = ed
	w.responseWriter.Reset(writer, "")
}

func (w *responseWriterWrapper) encode_questions(qs []dns.Question) {
	for i, _ := range qs {
		qs[i].Name = encode_name(qs[i].Name, w.encodingDomain)
	}

}

func (w *responseWriterWrapper) encode_rrs(rrs []dns.RR) {
	for _, rr := range rrs {
		header := rr.Header()
		header.Name = encode_name(header.Name, w.encodingDomain)

		if cname, ok := rr.(*dns.CNAME); ok {
			cname.Target = encode_name(cname.Target, w.encodingDomain)
		}
	}
}

func encode_name(name, domain string) string {
	name = base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(name))
	labels := chunks(name, 63)
	dotName := strings.Join(labels, ".")
	return dotName + "." + domain
}

func chunks(s string, chunkSize int) []string {
	if chunkSize >= len(s) {
		return []string{s}
	}
	var chunks []string
	chunk := make([]rune, chunkSize)
	len := 0
	for _, r := range s {
		chunk[len] = r
		len++
		if len == chunkSize {
			chunks = append(chunks, string(chunk))
			len = 0
		}
	}
	if len > 0 {
		chunks = append(chunks, string(chunk[:len]))
	}
	return chunks
}
