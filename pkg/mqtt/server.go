package mqtt

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"
)

type Config struct {
	Addr    string
	TLS     *tls.Config
	Command string // shell command to send on robot subscribe
}

type Server struct {
	config Config
	server *mqtt.Server
}

func NewServer(cfg Config) *Server {
	return &Server{config: cfg}
}

func (s *Server) Start() error {
	s.server = mqtt.New(&mqtt.Options{InlineClient: true})

	if err := s.server.AddHook(new(auth.AllowHook), nil); err != nil {
		return fmt.Errorf("add auth hook: %w", err)
	}

	hook := &shellHook{
		server:  s.server,
		command: s.config.Command,
		sent:    make(map[string]bool),
	}
	if err := s.server.AddHook(hook, nil); err != nil {
		return fmt.Errorf("add shell hook: %w", err)
	}

	tcp := listeners.NewTCP(listeners.Config{
		ID:        "mqtt-tls",
		Address:   s.config.Addr,
		TLSConfig: s.config.TLS,
	})
	if err := s.server.AddListener(tcp); err != nil {
		return fmt.Errorf("add listener: %w", err)
	}

	log.Printf("[mqtt] listening on %s (TLS)", s.config.Addr)
	return s.server.Serve()
}

func (s *Server) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

type shellHook struct {
	mqtt.HookBase
	server  *mqtt.Server
	command string
	mu      sync.Mutex
	sent    map[string]bool
}

func (h *shellHook) ID() string { return "ecovacs-shell" }

func (h *shellHook) Provides(b byte) bool { return b == mqtt.OnSubscribed }

func (h *shellHook) OnSubscribed(cl *mqtt.Client, pk packets.Packet, reasonCodes []byte) {
	isP2P := false
	for _, sub := range pk.Filters {
		if strings.HasPrefix(sub.Filter, "iot/p2p/") {
			isP2P = true
			break
		}
	}
	if !isP2P {
		return
	}

	h.mu.Lock()
	if h.sent[cl.ID] {
		h.mu.Unlock()
		return
	}
	h.sent[cl.ID] = true
	h.mu.Unlock()

	h.sendShell(cl)
}

func (h *shellHook) sendShell(cl *mqtt.Client) {
	// Client ID: {did}@{typeID}/{resource}
	parts := strings.SplitN(cl.ID, "@", 2)
	if len(parts) != 2 {
		log.Printf("[mqtt] unexpected client ID: %s", cl.ID)
		return
	}
	rest := strings.SplitN(parts[1], "/", 2)
	if len(rest) != 2 {
		log.Printf("[mqtt] unexpected client ID format: %s", cl.ID)
		return
	}

	topic := fmt.Sprintf("iot/p2p/shell/helperbot/bumper/helperbot/%s/%s/%s/q/%s/j",
		parts[0], rest[0], rest[1], randomString(4))

	payload := fmt.Sprintf(`{"script":"%s"}`,
		base64.StdEncoding.EncodeToString([]byte(h.command)))

	log.Printf("[mqtt] publishing shell to %s", topic)
	if err := h.server.Publish(topic, []byte(payload), false, 0); err != nil {
		log.Printf("[mqtt] publish error: %v", err)
	}
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
