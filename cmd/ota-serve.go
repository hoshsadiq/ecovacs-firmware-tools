package cmd

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/denysvitali/ecovacs-firmware-tools/pkg/dns"
	"github.com/denysvitali/ecovacs-firmware-tools/pkg/mqtt"
	"github.com/spf13/cobra"
)

type otaConfig struct {
	fwBinary string
	addr     string
	certFile string
	keyFile  string
	fwVer    string
	product  string
	manifest string
	force    bool
	buildNum int
	ip       string
	mqttOn   bool
	dnsOn    bool
	shellCmd string
	upstream string
}

func newOtaServeCmd() *cobra.Command {
	var cfg otaConfig

	cmd := &cobra.Command{
		Use:   "ota-serve --fw <firmware.bin>",
		Short: "Serve modified firmware as an OTA update",
		Long: `Run HTTPS + MQTT + DNS servers to push firmware to the robot.

HTTPS serves the firmware binary. MQTT (with --mqtt) sends a shell
command to the robot via the Ecovacs shell topic, triggering an
immediate download and flash. DNS (with --dns) redirects Ecovacs
domains to this machine.

The robot uses --no-check-certificate, so self-signed certs work.

Examples:
  # HTTPS only (robot must be told to check via other means)
  ecovacs-firmware-tools ota-serve --fw patched.bin

  # Full stack: HTTPS + MQTT + DNS (one-command OTA push)
  ecovacs-firmware-tools ota-serve --fw patched.bin --mqtt --dns --ip 192.168.1.50

  # Custom shell command instead of default download+flash
  ecovacs-firmware-tools ota-serve --fw patched.bin --mqtt --ip 192.168.1.50 \
    --cmd "wget -q https://192.168.1.50/fw.bin -O /tmp/fw.bin && fw_cut.sh /tmp/fw.bin"`,
		Run: func(cmd *cobra.Command, args []string) {
			runOtaServe(&cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.fwBinary, "fw", "", "Path to repacked firmware .bin (required)")
	cmd.Flags().StringVar(&cfg.addr, "addr", ":443", "HTTPS listen address")
	cmd.Flags().StringVar(&cfg.certFile, "cert", "", "TLS certificate file (auto-generated if omitted)")
	cmd.Flags().StringVar(&cfg.keyFile, "key", "", "TLS key file (auto-generated if omitted)")
	cmd.Flags().StringVar(&cfg.fwVer, "fw-ver", "", "Firmware version in OTA response")
	cmd.Flags().StringVar(&cfg.product, "product", "", "Product model in OTA response")
	cmd.Flags().StringVar(&cfg.manifest, "manifest", "", "Read fw_ver/product from decrypted manifest.json")
	cmd.Flags().BoolVar(&cfg.force, "force", false, "Mark update as forced")
	cmd.Flags().IntVar(&cfg.buildNum, "build-num", 9999, "Build number in OTA response")
	cmd.Flags().StringVar(&cfg.ip, "ip", "", "This machine's LAN IP (required for --mqtt/--dns)")
	cmd.Flags().BoolVar(&cfg.mqttOn, "mqtt", false, "Start fake MQTT broker (sends shell command to robot)")
	cmd.Flags().BoolVar(&cfg.dnsOn, "dns", false, "Start DNS server (redirects ecouser domains to --ip)")
	cmd.Flags().StringVar(&cfg.shellCmd, "cmd", "", "Custom shell command (default: download firmware + fw_cut.sh)")
	cmd.Flags().StringVar(&cfg.upstream, "upstream", "8.8.8.8:53", "Upstream DNS for non-Ecovacs queries")

	return cmd
}

type otaResponse struct {
	Version string      `json:"version"`
	Force   bool        `json:"force"`
	Fw0     otaFirmware `json:"fw0"`
}

type otaFirmware struct {
	URL      string `json:"url"`
	Size     int64  `json:"size"`
	CheckSum string `json:"checkSum"`
	BuildNum int    `json:"buildNum"`
}

func runOtaServe(cfg *otaConfig) {
	if cfg.fwBinary == "" {
		exitWithError("--fw is required")
	}
	if (cfg.mqttOn || cfg.dnsOn) && cfg.ip == "" {
		exitWithError("--ip is required when using --mqtt or --dns")
	}

	fwData, err := os.ReadFile(cfg.fwBinary)
	if err != nil {
		exitWithError("Cannot read firmware: %v", err)
	}

	fwMD5 := fmt.Sprintf("%x", md5.Sum(fwData))
	fwSize := int64(len(fwData))

	if cfg.manifest != "" {
		if v, p, err := readManifestVersion(cfg.manifest); err == nil {
			if cfg.fwVer == "" {
				cfg.fwVer = v
			}
			if cfg.product == "" {
				cfg.product = p
			}
		} else {
			fmt.Println(renderWarning(fmt.Sprintf("Cannot read manifest: %v", err)))
		}
	}
	if cfg.fwVer == "" {
		cfg.fwVer = "0.0.0"
		fmt.Println(renderWarning("No --fw-ver or --manifest; using version '0.0.0'"))
	}
	if cfg.product == "" {
		cfg.product = "unknown"
	}

	fwFileName := filepath.Base(cfg.fwBinary)

	if cfg.shellCmd == "" && cfg.ip != "" {
		cfg.shellCmd = fmt.Sprintf("wget --no-check-certificate https://%s/fw.bin -O /tmp/fw.bin && fw_cut.sh /tmp/fw.bin", cfg.ip)
	}

	tlsConfig, err := loadOrGenerateTLS(cfg.certFile, cfg.keyFile)
	if err != nil {
		exitWithError("TLS: %v", err)
	}

	fmt.Println(renderInfo(fmt.Sprintf("Serving: %s v%s (product: %s)", fwFileName, cfg.fwVer, cfg.product)))
	fmt.Println(renderInfo(fmt.Sprintf("MD5:     %s", fwMD5)))
	fmt.Println(renderInfo(fmt.Sprintf("Size:    %d bytes", fwSize)))
	fmt.Println(renderInfo(fmt.Sprintf("HTTPS:   %s", cfg.addr)))
	if cfg.ip != "" {
		fmt.Println(renderInfo(fmt.Sprintf("LAN IP:  %s", cfg.ip)))
	}
	if cfg.shellCmd != "" {
		fmt.Println(renderInfo(fmt.Sprintf("Shell:   %s", cfg.shellCmd)))
	}
	fmt.Println()

	// HTTPS
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ota/products/wukong/class/", otaMetadataHandler(cfg, fwData, fwMD5, fwFileName))
	mux.HandleFunc("/firmware/", firmwareHandler(fwData))
	mux.HandleFunc("/fw.bin", firmwareHandler(fwData))

	httpsServer := &http.Server{Addr: cfg.addr, Handler: mux, TLSConfig: tlsConfig}
	fmt.Println(renderSuccess(fmt.Sprintf("HTTPS listening on %s", cfg.addr)))

	// MQTT
	if cfg.mqttOn {
		mqttServer := mqtt.NewServer(mqtt.Config{Addr: ":8883", TLS: tlsConfig, Command: cfg.shellCmd})
		go func() {
			if err := mqttServer.Start(); err != nil {
				fmt.Println(renderError(fmt.Sprintf("MQTT error: %v", err)))
			}
		}()
		fmt.Println(renderSuccess("MQTT listening on :8883 (TLS)"))
	}

	// DNS
	if cfg.dnsOn {
		dnsIP := net.ParseIP(cfg.ip)
		if dnsIP == nil {
			exitWithError("Invalid --ip address: %s", cfg.ip)
		}
		dnsServer := dns.NewServer(dns.Config{Addr: ":53", IP: dnsIP, Domains: []string{"ecouser.net", "ecovacs.com"}, Upstream: cfg.upstream})
		go func() {
			if err := dnsServer.Start(); err != nil {
				fmt.Println(renderError(fmt.Sprintf("DNS error: %v", err)))
			}
		}()
		fmt.Println(renderSuccess(fmt.Sprintf("DNS listening on :53 → %s", cfg.ip)))
	}

	// Usage hint
	switch {
	case cfg.dnsOn:
		fmt.Println(infoStyle.Render("Point your router's DNS to this machine, or set robot DNS manually."))
	case cfg.mqttOn:
		fmt.Println(infoStyle.Render("Redirect mq.ecouser.net DNS to this machine for MQTT interception."))
	default:
		fmt.Println(infoStyle.Render("Point portal.ecouser.net DNS to this machine to intercept OTA."))
	}
	fmt.Println()

	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		exitWithError("Server error: %v", err)
	}
}

func otaMetadataHandler(cfg *otaConfig, fwData []byte, fwMD5, fwFileName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/firmware/latest.json") {
			http.NotFound(w, r)
			return
		}

		host := r.Host
		if host == "" {
			host = cfg.addr
		}
		if strings.HasPrefix(host, ":") {
			host = "localhost" + host
		}

		resp := otaResponse{
			Version: cfg.fwVer,
			Force:   cfg.force,
			Fw0: otaFirmware{
				URL:      fmt.Sprintf("https://%s/firmware/%s", host, fwFileName),
				Size:     int64(len(fwData)),
				CheckSum: fwMD5,
				BuildNum: cfg.buildNum,
			},
		}

		var model string
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		for i, p := range parts {
			if p == "class" && i+1 < len(parts) {
				model = parts[i+1]
				break
			}
		}

		fmt.Println(renderSuccess(fmt.Sprintf("OTA check: model=%s version=%s", model, cfg.fwVer)))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func firmwareHandler(data []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		n, _ := w.Write(data)
		fmt.Println(renderSuccess(fmt.Sprintf("FW download: %d bytes → %s", n, r.RemoteAddr)))
	}
}

func readManifestVersion(path string) (fwVer, product string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	var m struct {
		FwVer   string `json:"fw_ver"`
		Product string `json:"product"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", "", err
	}
	return m.FwVer, m.Product, nil
}

func loadOrGenerateTLS(certFile, keyFile string) (*tls.Config, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	fmt.Println(renderWarning("No cert provided — generating self-signed certificate"))
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "portal.ecouser.net"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{
			"portal.ecouser.net", "portal-ww.ecouser.net",
			"mq.ecouser.net", "lb.ecouser.net", "localhost",
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
