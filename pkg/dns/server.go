package dns

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"time"
)

type Config struct {
	Addr     string
	IP       net.IP
	Domains  []string
	Upstream string // forward non-matching queries here (e.g. "8.8.8.8:53")
}

type Server struct {
	config Config
	conn   *net.UDPConn
}

func NewServer(cfg Config) *Server {
	return &Server{config: cfg}
}

func (s *Server) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.config.Addr)
	if err != nil {
		return err
	}
	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	log.Printf("[dns] listening on %s → %s (upstream: %s)", s.config.Addr, s.config.IP, s.config.Upstream)

	buf := make([]byte, 512)
	for {
		n, remote, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		go s.handleQuery(buf[:n], remote)
	}
}

func (s *Server) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *Server) handleQuery(query []byte, remote *net.UDPAddr) {
	if len(query) < 12 {
		return
	}

	name, offset := parseDNSName(query, 12)
	if offset+4 > len(query) {
		return
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])

	intercept := false
	for _, d := range s.config.Domains {
		if strings.EqualFold(name, d) || strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(d)) {
			intercept = true
			break
		}
	}

	if intercept && qtype == 1 {
		log.Printf("[dns] %s → %s (from %s)", name, s.config.IP, remote)
		s.writeResponse(buildAResponse(query, offset, s.config.IP), remote)
		return
	}

	if s.config.Upstream != "" {
		resp, err := s.forward(query)
		if err != nil {
			log.Printf("[dns] forward %s: %v", name, err)
			return
		}
		s.writeResponse(resp, remote)
		return
	}

	s.writeResponse(buildNXDOMAIN(query), remote)
}

func (s *Server) forward(query []byte) ([]byte, error) {
	upstream, err := net.ResolveUDPAddr("udp", s.config.Upstream)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *Server) writeResponse(resp []byte, remote *net.UDPAddr) {
	s.conn.WriteToUDP(resp, remote)
}

func parseDNSName(data []byte, offset int) (string, int) {
	var parts []string
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length > 63 {
			offset += 2
			break
		}
		offset++
		if offset+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, "."), offset
}

func buildAResponse(query []byte, questionEnd int, ip net.IP) []byte {
	question := query[12 : questionEnd+4]

	resp := make([]byte, 0, 512)
	resp = append(resp, query[0], query[1])
	resp = append(resp, 0x81, 0x80)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)

	resp = append(resp, question...)

	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, ip.To4()...)

	return resp
}

func buildNXDOMAIN(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x81
	resp[3] = 0x83
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}
