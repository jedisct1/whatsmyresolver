package resolver

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

type Server struct {
	Address string
}

func New(address string) *Server {
	return &Server{Address: address}
}

func (s *Server) Start() error {
	dns.HandleFunc(".", s.route)
	defer dns.HandleRemove(".")

	udpServer := &dns.Server{Addr: s.Address, Net: "udp"}
	defer udpServer.Shutdown()

	udpAddr, err := net.ResolveUDPAddr(udpServer.Net, udpServer.Addr)
	if err != nil {
		return err
	}

	udpPacketConn, err := net.ListenUDP(udpServer.Net, udpAddr)
	if err != nil {
		return err
	}

	udpServer.PacketConn = udpPacketConn
	fmt.Println("Ready")

	if err := udpServer.ActivateAndServe(); err != nil {
		return err
	}

	return nil
}

func (s *Server) route(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		s.failWithRcode(w, req, dns.RcodeRefused)
		return
	}

	question := req.Question[0]
	qtype := question.Qtype

	if question.Qclass != dns.ClassINET {
		s.failWithRcode(w, req, dns.RcodeRefused)
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
		m.Answer = s.buildTXTRecords(question, remoteIP, req)
	}

	m.Question = req.Question
	m.Response = true
	m.Authoritative = true

	if err := w.WriteMsg(m); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) failWithRcode(w dns.ResponseWriter, r *dns.Msg, rCode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rCode)
	if err := w.WriteMsg(m); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) buildTXTRecords(question dns.Question, remoteIP net.IP, req *dns.Msg) []dns.RR {
	var answers []dns.RR

	createTXT := func(text string) *dns.TXT {
		rr := new(dns.TXT)
		rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: question.Qtype,
			Class: dns.ClassINET, Ttl: 10}
		rr.Txt = []string{text}
		return rr
	}

	answers = append(answers, createTXT(fmt.Sprintf("Resolver IP: %v", remoteIP.String())))

	if req.AuthenticatedData {
		answers = append(answers, createTXT("AD flag set (Authenticated Data)"))
	}
	if req.CheckingDisabled {
		answers = append(answers, createTXT("CD flag set (Checking Disabled)"))
	}
	if req.RecursionDesired {
		answers = append(answers, createTXT("RD flag set (Recursion Desired)"))
	}

	if edns0 := req.IsEdns0(); edns0 != nil {
		if edns0.Do() {
			answers = append(answers, createTXT("DNSSEC OK (DO bit set)"))
		}

		answers = append(answers, createTXT(fmt.Sprintf("EDNS0 UDP buffer size: %d", edns0.UDPSize())))

		for _, option := range edns0.Option {
			switch option.Option() {
			case dns.EDNS0PADDING:
				ext := option.(*dns.EDNS0_PADDING)
				paddingLen := len(ext.Padding)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 padding: %v bytes", paddingLen)))
			case dns.EDNS0SUBNET:
				ext := option.(*dns.EDNS0_SUBNET)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 client subnet: %v", ext.String())))
			case dns.EDNS0NSID:
				ext := option.(*dns.EDNS0_NSID)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 nsid: %v", ext.Nsid)))
			case dns.EDNS0COOKIE:
				ext := option.(*dns.EDNS0_COOKIE)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 cookie: %v", ext.Cookie)))
			case dns.EDNS0TCPKEEPALIVE:
				ext := option.(*dns.EDNS0_TCP_KEEPALIVE)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 TCP keepalive: timeout=%d, length=%d", ext.Timeout, ext.Length)))
			case dns.EDNS0EXPIRE:
				ext := option.(*dns.EDNS0_EXPIRE)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 expire: %d", ext.Expire)))
			case dns.EDNS0DAU:
				ext := option.(*dns.EDNS0_DAU)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 DNSSEC algorithms understood: %v", ext.AlgCode)))
			case dns.EDNS0DHU:
				ext := option.(*dns.EDNS0_DHU)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 DS hash understood: %v", ext.AlgCode)))
			case dns.EDNS0N3U:
				ext := option.(*dns.EDNS0_N3U)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 NSEC3 hash understood: %v", ext.AlgCode)))
			case dns.EDNS0EDE:
				ext := option.(*dns.EDNS0_EDE)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 extended DNS error: code=%d, info=%s", ext.InfoCode, ext.ExtraText)))
			case dns.EDNS0ESU:
				ext := option.(*dns.EDNS0_ESU)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 ENUM source-URI: %s", ext.Uri)))
			case dns.EDNS0LLQ:
				ext := option.(*dns.EDNS0_LLQ)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 long lived query: version=%d, opcode=%d", ext.Version, ext.Opcode)))
			case dns.EDNS0UL:
				ext := option.(*dns.EDNS0_UL)
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 update lease: lease=%d", ext.Lease)))
			default:
				answers = append(answers, createTXT(fmt.Sprintf("EDNS0 unknown option: code=%d", option.Option())))
			}
		}
	}

	return answers
}

