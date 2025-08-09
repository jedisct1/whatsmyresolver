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
	if err := w.WriteMsg(m); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
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

		// Report DNS flags
		if req.AuthenticatedData {
			rr.Txt = append(rr.Txt, "AD flag set (Authenticated Data)")
		}
		if req.CheckingDisabled {
			rr.Txt = append(rr.Txt, "CD flag set (Checking Disabled)")
		}
		if req.RecursionDesired {
			rr.Txt = append(rr.Txt, "RD flag set (Recursion Desired)")
		}

		if edns0 := req.IsEdns0(); edns0 != nil {
			// Report DNSSEC OK bit
			if edns0.Do() {
				rr.Txt = append(rr.Txt, "DNSSEC OK (DO bit set)")
			}

			// Report EDNS0 buffer size
			rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 UDP buffer size: %d", edns0.UDPSize()))

			for _, option := range edns0.Option {
				switch option.Option() {
				case dns.EDNS0PADDING:
					ext := option.(*dns.EDNS0_PADDING)
					paddingLen := len(ext.Padding)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 padding: %v bytes", paddingLen))
				case dns.EDNS0SUBNET:
					ext := option.(*dns.EDNS0_SUBNET)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 client subnet: %v", ext.String()))
				case dns.EDNS0NSID:
					ext := option.(*dns.EDNS0_NSID)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 nsid: %v", ext.Nsid))
				case dns.EDNS0COOKIE:
					ext := option.(*dns.EDNS0_COOKIE)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 cookie: %v", ext.Cookie))
				case dns.EDNS0TCPKEEPALIVE:
					ext := option.(*dns.EDNS0_TCP_KEEPALIVE)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 TCP keepalive: timeout=%d, length=%d", ext.Timeout, ext.Length))
				case dns.EDNS0EXPIRE:
					ext := option.(*dns.EDNS0_EXPIRE)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 expire: %d", ext.Expire))
				case dns.EDNS0DAU:
					ext := option.(*dns.EDNS0_DAU)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 DNSSEC algorithms understood: %v", ext.AlgCode))
				case dns.EDNS0DHU:
					ext := option.(*dns.EDNS0_DHU)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 DS hash understood: %v", ext.AlgCode))
				case dns.EDNS0N3U:
					ext := option.(*dns.EDNS0_N3U)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 NSEC3 hash understood: %v", ext.AlgCode))
				case dns.EDNS0EDE:
					ext := option.(*dns.EDNS0_EDE)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 extended DNS error: code=%d, info=%s", ext.InfoCode, ext.ExtraText))
				case dns.EDNS0ESU:
					ext := option.(*dns.EDNS0_ESU)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 ENUM source-URI: %s", ext.Uri))
				case dns.EDNS0LLQ:
					ext := option.(*dns.EDNS0_LLQ)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 long lived query: version=%d, opcode=%d", ext.Version, ext.Opcode))
				case dns.EDNS0UL:
					ext := option.(*dns.EDNS0_UL)
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 update lease: lease=%d", ext.Lease))
				default:
					// Report unknown EDNS0 options
					rr.Txt = append(rr.Txt, fmt.Sprintf("EDNS0 unknown option: code=%d", option.Option()))
				}
			}
		}

		m.Answer = []dns.RR{rr}
	}
	m.Question = req.Question
	m.Response = true
	m.Authoritative = true
	if err := w.WriteMsg(m); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
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
	if err := udpServer.ActivateAndServe(); err != nil {
		log.Fatal(err)
	}
}
