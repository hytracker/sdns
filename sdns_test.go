package main

import (
	"net"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/stretchr/testify/assert"
	"github.com/yl2chen/cidranger"
)

const (
	testDomain = "www.google.com"
)

var (
	ginr *gin.Engine
)

func TestMain(m *testing.M) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	Config.Maxdepth = 30
	Config.Interval = 1000
	Config.Timeout = 2
	Config.Maxdepth = 30
	Config.Expire = 600
	Config.ConnectTimeout = 1
	Config.Nullroute = "0.0.0.0"
	Config.Nullroutev6 = "0:0:0:0:0:0:0:0"
	Config.Bind = ":0"
	Config.BindTLS = ""
	Config.BindDOH = ""
	Config.API = ""

	AccessList = cidranger.NewPCTrieRanger()
	_, ipnet, _ := net.ParseCIDR("0.0.0.0/0")
	AccessList.Insert(cidranger.NewBasicRangerEntry(*ipnet))
	_, ipnet, _ = net.ParseCIDR("::0/0")
	AccessList.Insert(cidranger.NewBasicRangerEntry(*ipnet))

	gin.SetMode(gin.TestMode)
	ginr = gin.New()

	block := ginr.Group("/api/v1/block")
	{
		block.GET("/exists/:key", existsBlock)
		block.GET("/get/:key", getBlock)
		block.GET("/remove/:key", removeBlock)
		block.GET("/set/:key", setBlock)
	}

	m.Run()
}

func Test_start(t *testing.T) {
	configSetup(true)
	start()

	time.Sleep(2 * time.Second)
}

func BenchmarkExchange(b *testing.B) {
	s, addrstr, err := RunLocalUDPServer("127.0.0.1:0")
	assert.NoError(b, err)

	defer s.Shutdown()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	req.RecursionDesired = true

	c := new(dns.Client)

	//caching
	_, _, err = c.Exchange(req, addrstr)
	assert.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Exchange(req, addrstr)
	}
}

func BenchmarkResolver(b *testing.B) {
	r := NewResolver()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("www.netdirekt.com.tr"), dns.TypeA)
	req.RecursionDesired = true
	req.SetEdns0(DefaultMsgSize, true)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)
	}
}

func BenchmarkUDPHandler(b *testing.B) {
	h := NewHandler()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	req.RecursionDesired = true
	req.SetEdns0(DefaultMsgSize, true)

	//caching
	resp := h.query("udp", req)
	assert.NotNil(b, resp)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.query("udp", req)
	}
}

func BenchmarkTCPHandler(b *testing.B) {
	h := NewHandler()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	req.RecursionDesired = true

	//caching
	resp := h.query("tcp", req)
	assert.NotNil(b, resp)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.query("tcp", req)
	}
}
