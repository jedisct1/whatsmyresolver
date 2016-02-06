package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

var (
	address = flag.String("listen", ":53", "Address to listen to (UDP)")
)

func failWithRcode(w dns.ResponseWriter, r *dns.Msg, rCode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rCode)
	w.WriteMsg(m)
}

func route(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		failWithRcode(w, req, dns.RcodeRefused)
		return
	}
	question := req.Question[0]
	qtype := question.Qtype
	if question.Qclass != dns.ClassINET {
		failWithRcode(w, req, dns.RcodeRefused)
		return
	}
	remoteIP := w.RemoteAddr().(*net.UDPAddr).IP
	m := new(dns.Msg)
	m.Id = req.Id
	switch qtype {
	case dns.TypeA:
		if remoteIP4 := remoteIP.To4(); remoteIP4 != nil {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: question.Qtype,
				Class: dns.ClassINET, Ttl: 10}
			rr.A = remoteIP4
			m.Answer = []dns.RR{rr}
		}
	case dns.TypeAAAA:
		if remoteIP16 := remoteIP.To16(); remoteIP16 != nil {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: question.Qtype,
				Class: dns.ClassINET, Ttl: 10}
			rr.AAAA = remoteIP16
			m.Answer = []dns.RR{rr}
		}
	case dns.TypeTXT:
		rr := new(dns.TXT)
		rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: question.Qtype,
			Class: dns.ClassINET, Ttl: 10}
		rr.Txt = []string{fmt.Sprintf("Resolver IP: %v", remoteIP.String())}
		m.Answer = []dns.RR{rr}
	}
	m.Question = req.Question
	m.Response = true
	m.Authoritative = true
	w.WriteMsg(m)
}

func main() {
	flag.Parse()
	dns.HandleFunc(".", route)
	defer dns.HandleRemove(".")
	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	defer udpServer.Shutdown()
	udpAddr, err := net.ResolveUDPAddr(udpServer.Net, udpServer.Addr)
	if err != nil {
		log.Fatal(err)
	}
	udpPacketConn, err := net.ListenUDP(udpServer.Net, udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	udpServer.PacketConn = udpPacketConn
	fmt.Println("Ready")
	udpServer.ActivateAndServe()
}
