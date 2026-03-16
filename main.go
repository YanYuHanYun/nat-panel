package main

import (
	_ "embed"
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	netio "github.com/shirou/gopsutil/v3/net"
	"gopkg.in/yaml.v3"
)

const (
	cmdTimeout    = 8 * time.Second
	defaultDBPath = "/var/lib/firewall-api/state.db"
	appVersion    = "0.0.1"
	ruleTagPrefix = "fwapi:"
	acctChainName = "FWAPI_ACCT"
	tcpAckMaxLen  = 128
)

type Config struct {
	Server struct {
		Listen string `yaml:"listen"`
	} `yaml:"server"`

	Auth struct {
		BearerToken string `yaml:"bearer_token"`
	} `yaml:"auth"`

	Panel struct {
		Enabled *bool `yaml:"enabled"`
	} `yaml:"panel"`

	CORS struct {
		AllowOrigins []string `yaml:"allow_origins"`
	} `yaml:"cors"`

	Firewall struct {
		DefaultForwardPolicy string `yaml:"default_forward_policy"`

		IPv4 struct {
			SavePath         string `yaml:"save_path"`
			EnableMasquerade bool   `yaml:"enable_masquerade"`
		} `yaml:"ipv4"`

		IPv6 struct {
			SavePath         string `yaml:"save_path"`
			EnableMasquerade bool   `yaml:"enable_masquerade"`
		} `yaml:"ipv6"`
	} `yaml:"firewall"`

	Monitor struct {
		CPUIntervalSeconds     int    `yaml:"cpu_interval_seconds"`
		NetworkIntervalSeconds int    `yaml:"network_interval_seconds"`
		StatsPollSeconds       int    `yaml:"stats_poll_seconds"`
		DBPath                 string `yaml:"db_path"`
	} `yaml:"monitor"`
}

type Server struct {
	cfg        Config
	osType     string
	mux        *http.ServeMux
	db         *sql.DB
	netMonitor *NetworkMonitor
	cpuMonitor *CPUMonitor

	ruleRealtimeMu sync.RWMutex
	ruleRealtime   map[string]RuleRealtimeState
}

type APIError struct {
	Error string `json:"error"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type StatusResponse struct {
	OS             string `json:"os"`
	IPForward4     bool   `json:"ipForward4"`
	IPForward6     bool   `json:"ipForward6"`
	HasIptables    bool   `json:"hasIptables"`
	HasIp6tables   bool   `json:"hasIp6tables"`
	IPv4Masquerade bool   `json:"ipv4Masquerade"`
	IPv6Masquerade bool   `json:"ipv6Masquerade"`
}

type Rule struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Family        string `json:"family"`
	Protocol      string `json:"protocol"`
	LocalPort     int    `json:"localPort"`
	InboundIP     string `json:"inboundIp"`
	TargetIP      string `json:"targetIp"`
	TargetPort    int    `json:"targetPort"`
	OutboundIP    string `json:"outboundIp"`
	ConnLimit     int    `json:"connLimit"`
	BandwidthKbps int    `json:"bandwidthKbps"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

type CreateRuleRequest struct {
	Name          string `json:"name"`
	Family        string `json:"family"`
	Protocol      string `json:"protocol"`
	LocalPort     int    `json:"localPort"`
	InboundIP     string `json:"inboundIp"`
	TargetIP      string `json:"targetIp"`
	TargetPort    int    `json:"targetPort"`
	OutboundIP    string `json:"outboundIp"`
	ConnLimit     int    `json:"connLimit"`
	BandwidthKbps int    `json:"bandwidthKbps"`
}

type RuleSpec struct {
	Name          string `json:"name"`
	Family        string `json:"family"`
	Protocol      string `json:"protocol"`
	LocalPort     int    `json:"localPort"`
	InboundIP     string `json:"inboundIp"`
	TargetIP      string `json:"targetIp"`
	TargetPort    int    `json:"targetPort"`
	OutboundIP    string `json:"outboundIp"`
	ConnLimit     int    `json:"connLimit"`
	BandwidthKbps int    `json:"bandwidthKbps"`
}

type UpdateRuleRequest struct {
	ID  string   `json:"id"`
	New RuleSpec `json:"new"`
}

type DeleteRuleRequest struct {
	ID string `json:"id"`
}

type ProtocolStats struct {
	TrafficBytes uint64 `json:"trafficBytes"`
	TrafficPkts  uint64 `json:"trafficPkts"`
}

type ProtocolRealtime struct {
	BytesPerSec uint64 `json:"bytesPerSec"`
	PktsPerSec  uint64 `json:"pktsPerSec"`
}

type RuleRealtimeState struct {
	SampleInterval  int              `json:"sampleIntervalSeconds"`
	Total           ProtocolRealtime `json:"total"`
	TCP             ProtocolRealtime `json:"tcp"`
	UDP             ProtocolRealtime `json:"udp"`
	LastUpdatedUnix int64            `json:"lastUpdatedUnix"`
}

type RuleMetricTotals struct {
	Total ProtocolStats `json:"total"`
	TCP   ProtocolStats `json:"tcp"`
	UDP   ProtocolStats `json:"udp"`
}

type RuleMetricRates struct {
	Total ProtocolRealtime `json:"total"`
	TCP   ProtocolRealtime `json:"tcp"`
	UDP   ProtocolRealtime `json:"udp"`
}

type RuleMetricsResponse struct {
	ID                    string          `json:"id"`
	Family                string          `json:"family"`
	Protocol              string          `json:"protocol"`
	LocalPort             int             `json:"localPort"`
	TargetIP              string          `json:"targetIp"`
	TargetPort            int             `json:"targetPort"`
	SampleIntervalSeconds int             `json:"sampleIntervalSeconds"`
	Cumulative            RuleMetricTotals `json:"cumulative"`
	Realtime              RuleMetricRates  `json:"realtime"`
	LastUpdatedUnix       int64           `json:"lastUpdatedUnix"`
}

type RuleDiagnosticResponse struct {
	ID                   string  `json:"id"`
	Family               string  `json:"family"`
	Protocol             string  `json:"protocol"`
	TargetIP             string  `json:"targetIp"`
	TargetPort           int     `json:"targetPort"`
	ConfiguredOutboundIP string  `json:"configuredOutboundIp"`
	EffectiveOutboundIP  string  `json:"effectiveOutboundIp"`
	Method               string  `json:"method"`
	SampleCount          int     `json:"sampleCount"`
	SuccessfulSamples    int     `json:"successfulSamples"`
	LatencyMs            float64 `json:"latencyMs"`
	DiagnosedAt          string  `json:"diagnosedAt"`
}

type RuleListItem struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Family        string        `json:"family"`
	Protocol      string        `json:"protocol"`
	LocalPort     int           `json:"localPort"`
	InboundIP     string        `json:"inboundIp"`
	TargetIP      string        `json:"targetIp"`
	TargetPort    int           `json:"targetPort"`
	OutboundIP    string        `json:"outboundIp"`
	ConnLimit     int           `json:"connLimit"`
	BandwidthKbps int           `json:"bandwidthKbps"`
	Enabled       bool          `json:"enabled"`
	CreatedAt     string        `json:"createdAt"`
	UpdatedAt     string        `json:"updatedAt"`
	Total         ProtocolStats `json:"total"`
	TCP           ProtocolStats `json:"tcp"`
	UDP           ProtocolStats `json:"udp"`
	Realtime      RuleMetricRates `json:"realtime"`
}

type SystemInfoResponse struct {
	Hostname           string `json:"hostname"`
	OS                 string `json:"os"`
	Platform           string `json:"platform"`
	PlatformFamily     string `json:"platformFamily"`
	PlatformVersion    string `json:"platformVersion"`
	KernelVersion      string `json:"kernelVersion"`
	KernelArch         string `json:"kernelArch"`
	Virtualization     string `json:"virtualization"`
	VirtualizationRole string `json:"virtualizationRole"`
	BootTime           uint64 `json:"bootTime"`
	GoOS               string `json:"goOS"`
	GoArch             string `json:"goArch"`
	CPUCoresLogical    int    `json:"cpuCoresLogical"`
}

type UptimeResponse struct {
	BootTime       uint64 `json:"bootTime"`
	UptimeSeconds  uint64 `json:"uptimeSeconds"`
	UptimeReadable string `json:"uptimeReadable"`
}

type CPUResponse struct {
	ModelName      string  `json:"modelName"`
	LogicalCores   int     `json:"logicalCores"`
	UsagePercent   float64 `json:"usagePercent"`
	SampleDuration string  `json:"sampleDuration"`
	Cached         bool    `json:"cached"`
}

type MemoryResponse struct {
	Total       uint64  `json:"total"`
	Available   uint64  `json:"available"`
	Used        uint64  `json:"used"`
	UsedPercent float64 `json:"usedPercent"`
	Free        uint64  `json:"free"`
	Cached      uint64  `json:"cached"`
	Buffers     uint64  `json:"buffers"`
}

type DiskItem struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	FSType      string  `json:"fsType"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"usedPercent"`
}

type NetSnapshot struct {
	Name        string `json:"name"`
	BytesSent   uint64 `json:"bytesSent"`
	BytesRecv   uint64 `json:"bytesRecv"`
	PacketsSent uint64 `json:"packetsSent"`
	PacketsRecv uint64 `json:"packetsRecv"`
	Errin       uint64 `json:"errin"`
	Errout      uint64 `json:"errout"`
	Dropin      uint64 `json:"dropin"`
	Dropout     uint64 `json:"dropout"`
}

type NetRealtime struct {
	Name            string `json:"name"`
	IntervalSeconds int    `json:"intervalSeconds"`
	TxBytesPerSec   uint64 `json:"txBytesPerSec"`
	RxBytesPerSec   uint64 `json:"rxBytesPerSec"`
	TxHuman         string `json:"txHuman"`
	RxHuman         string `json:"rxHuman"`
}

type NetInterfaceAddress struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Prefix  int    `json:"prefix"`
}

type NetInterfaceData struct {
	Name            string `json:"name"`
	Addresses       []NetInterfaceAddress `json:"addresses"`
	BytesSent       uint64 `json:"bytesSent"`
	BytesRecv       uint64 `json:"bytesRecv"`
	BytesSentHuman  string `json:"bytesSentHuman"`
	BytesRecvHuman  string `json:"bytesRecvHuman"`
	PacketsSent     uint64 `json:"packetsSent"`
	PacketsRecv     uint64 `json:"packetsRecv"`
	Errin           uint64 `json:"errin"`
	Errout          uint64 `json:"errout"`
	Dropin          uint64 `json:"dropin"`
	Dropout         uint64 `json:"dropout"`
	IntervalSeconds int    `json:"intervalSeconds"`
	TxBytesPerSec   uint64 `json:"txBytesPerSec"`
	RxBytesPerSec   uint64 `json:"rxBytesPerSec"`
	TxHuman         string `json:"txHuman"`
	RxHuman         string `json:"rxHuman"`
}

type NetworkMonitor struct {
	mu       sync.RWMutex
	interval time.Duration
	lastAt   time.Time
	lastRaw  map[string]NetSnapshot
	stats    map[string]NetSnapshot
	rate     map[string]NetRealtime
}

type CPUMonitor struct {
	mu       sync.RWMutex
	interval time.Duration
	usage    float64
	model    string
	ready    bool
}

type counterRecord struct {
	RuleID   string
	Protocol string
	Pkts     uint64
	Bytes    uint64
}

var (
	saveCounterRe = regexp.MustCompile(`^\[(\d+):(\d+)\]\s+-A\s+(\S+)\s+`)
	commentQuoted = regexp.MustCompile(`--comment\s+"([^"]+)"`)
	commentBare   = regexp.MustCompile(`--comment\s+([^\s]+)`)
	pingStatsRe   = regexp.MustCompile(`=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms`)
	pingRecvRe    = regexp.MustCompile(`(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received`)
)

func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}
	applyDefaults(&cfg)

	if strings.TrimSpace(cfg.Auth.BearerToken) == "" {
		log.Fatal("auth.bearer_token is required")
	}

	osType, err := detectOS()
	if err != nil {
		log.Fatal(err)
	}

	db, err := openDB(cfg.Monitor.DBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatal(err)
	}

	cpuMonitor := NewCPUMonitor(time.Duration(cfg.Monitor.CPUIntervalSeconds) * time.Second)
	cpuMonitor.Start()

	netMonitor := NewNetworkMonitor(time.Duration(cfg.Monitor.NetworkIntervalSeconds) * time.Second)
	netMonitor.Start()

	s := &Server{
		cfg:          cfg,
		osType:       osType,
		mux:          http.NewServeMux(),
		db:           db,
		netMonitor:   netMonitor,
		cpuMonitor:   cpuMonitor,
		ruleRealtime: make(map[string]RuleRealtimeState),
	}
	s.routes()

	go s.startStatsSyncLoop()

	log.Printf("firewall api listening on %s, os=%s", cfg.Server.Listen, osType)
	if err := http.ListenAndServe(cfg.Server.Listen, s.mux); err != nil {
		log.Fatal(err)
	}
}

//go:embed index.html
var panelIndexHTML string

func applyDefaults(cfg *Config) {
	if cfg.Panel.Enabled == nil {
		enabled := true
		cfg.Panel.Enabled = &enabled
	}
	if strings.TrimSpace(cfg.Server.Listen) == "" {
		cfg.Server.Listen = "127.0.0.1:8080"
	}
	if strings.TrimSpace(cfg.Firewall.DefaultForwardPolicy) == "" {
		cfg.Firewall.DefaultForwardPolicy = "ACCEPT"
	}
	if strings.TrimSpace(cfg.Firewall.IPv4.SavePath) == "" {
		cfg.Firewall.IPv4.SavePath = "/etc/iptables/rules.v4"
	}
	if strings.TrimSpace(cfg.Firewall.IPv6.SavePath) == "" {
		cfg.Firewall.IPv6.SavePath = "/etc/iptables/rules.v6"
	}
	if cfg.Monitor.CPUIntervalSeconds <= 0 {
		cfg.Monitor.CPUIntervalSeconds = 1
	}
	if cfg.Monitor.NetworkIntervalSeconds <= 0 {
		cfg.Monitor.NetworkIntervalSeconds = 1
	}
	if cfg.Monitor.StatsPollSeconds <= 0 {
		cfg.Monitor.StatsPollSeconds = 5
	}
	if strings.TrimSpace(cfg.Monitor.DBPath) == "" {
		cfg.Monitor.DBPath = defaultDBPath
	}
}

func panelEnabled(cfg Config) bool {
	if cfg.Panel.Enabled == nil {
		return true
	}
	return *cfg.Panel.Enabled
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func detectOS() (string, error) {
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "centos", nil
	}
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian", nil
	}
	return "", errors.New("unsupported OS: only Debian/Ubuntu or CentOS/RedHat are supported")
}

func openDB(path string) (*sql.DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	pragmas := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA foreign_keys=ON;`,
		`PRAGMA busy_timeout=5000;`,
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

func initDB(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS rules (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL DEFAULT '',
	family TEXT NOT NULL,
	protocol TEXT NOT NULL,
	local_port INTEGER NOT NULL,
	inbound_ip TEXT NOT NULL DEFAULT '',
	target_ip TEXT NOT NULL,
	target_port INTEGER NOT NULL,
	outbound_ip TEXT NOT NULL DEFAULT '',
	conn_limit INTEGER NOT NULL DEFAULT 0,
	bandwidth_kbps INTEGER NOT NULL DEFAULT 0,
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_counters (
	rule_id TEXT NOT NULL,
	protocol TEXT NOT NULL,
	total_packets INTEGER NOT NULL DEFAULT 0,
	total_bytes INTEGER NOT NULL DEFAULT 0,
	last_kernel_packets INTEGER NOT NULL DEFAULT 0,
	last_kernel_bytes INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	PRIMARY KEY(rule_id, protocol),
	FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE
);
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	if err := ensureRuleColumn(db, "inbound_ip", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureRuleColumn(db, "name", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureRuleColumn(db, "outbound_ip", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := db.Exec(`DROP INDEX IF EXISTS idx_rules_unique`); err != nil {
		return err
	}
	_, err := db.Exec(`
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_unique
ON rules(family, protocol, local_port, inbound_ip, target_ip, target_port, outbound_ip)`)
	return err
}

func ensureRuleColumn(db *sql.DB, name, definition string) error {
	rows, err := db.Query(`PRAGMA table_info(rules)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var colName string
		var colType string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &colName, &colType, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(fmt.Sprintf(`ALTER TABLE rules ADD COLUMN %s %s`, name, definition))
	return err
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !panelEnabled(s.cfg) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(panelIndexHTML))
}

func (s *Server) routes() {
	api := http.NewServeMux()

	api.HandleFunc("/", s.handleRoot)

	api.Handle("/api/rules", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleListRules(w, r)
		case http.MethodPost:
			s.handleCreateRule(w, r)
		case http.MethodPut:
			s.handleUpdateRule(w, r)
		case http.MethodDelete:
			s.handleDeleteRule(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	api.Handle("/api/rules/metrics", s.auth(methodHandler(http.MethodGet, http.HandlerFunc(s.handleRuleMetrics))))
	api.Handle("/api/rules/diagnostics", s.auth(methodHandler(http.MethodGet, http.HandlerFunc(s.handleRuleDiagnostics))))

	api.Handle("/api/system", s.auth(methodHandler(http.MethodGet, http.HandlerFunc(s.handleSystem))))

	s.mux.Handle("/", s.cors(api))
}

func methodHandler(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			writeJSON(w, http.StatusUnauthorized, APIError{Error: "missing bearer token"})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Auth.BearerToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, APIError{Error: "invalid bearer token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" && s.isOriginAllowed(origin) {
			if s.hasWildcardOrigin() {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hasWildcardOrigin() bool {
	for _, v := range s.cfg.CORS.AllowOrigins {
		if strings.TrimSpace(v) == "*" {
			return true
		}
	}
	return false
}

func (s *Server) isOriginAllowed(origin string) bool {
	for _, v := range s.cfg.CORS.AllowOrigins {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if v == "*" {
			return true
		}
		if strings.EqualFold(v, origin) {
			return true
		}
	}
	return false
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	family := normalizeFamily(r.URL.Query().Get("family"))
	if family == "all" {
		family = ""
	}
	if family != "" && family != "ipv4" && family != "ipv6" {
		writeError(w, http.StatusBadRequest, errors.New("family must be ipv4 or ipv6"))
		return
	}

	items, err := listRulesFromDB(r.Context(), s.db, family)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.ruleRealtimeMu.RLock()
	for i := range items {
		rt := s.ruleRealtime[items[i].ID]
		rt.Total = ProtocolRealtime{
			BytesPerSec: rt.TCP.BytesPerSec + rt.UDP.BytesPerSec,
			PktsPerSec:  rt.TCP.PktsPerSec + rt.UDP.PktsPerSec,
		}
		items[i].Realtime = RuleMetricRates{
			Total: rt.Total,
			TCP:   rt.TCP,
			UDP:   rt.UDP,
		}
	}
	s.ruleRealtimeMu.RUnlock()
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleRuleMetrics(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}

	rule, err := getRuleByIDBasic(r.Context(), s.db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, errors.New("rule not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.ruleRealtimeMu.RLock()
	rt, ok := s.ruleRealtime[id]
	s.ruleRealtimeMu.RUnlock()

	if !ok {
		rt = RuleRealtimeState{}
	}

	tcpStats, udpStats, err := getRuleProtocolStats(r.Context(), s.db, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, buildRuleMetricsResponse(
		rule.ID,
		rule.Family,
		rule.Protocol,
		rule.LocalPort,
		rule.TargetIP,
		rule.TargetPort,
		ProtocolStats{TrafficBytes: tcpStats.TrafficBytes + udpStats.TrafficBytes, TrafficPkts: tcpStats.TrafficPkts + udpStats.TrafficPkts},
		tcpStats,
		udpStats,
		s.cfg.Monitor.StatsPollSeconds,
		rt,
	))
}

func buildRuleMetricsResponse(id, family, protocol string, localPort int, targetIP string, targetPort int, totalStats, tcpStats, udpStats ProtocolStats, sampleInterval int, rt RuleRealtimeState) RuleMetricsResponse {
	if rt.SampleInterval <= 0 {
		rt.SampleInterval = sampleInterval
	}
	rt.Total = ProtocolRealtime{
		BytesPerSec: rt.TCP.BytesPerSec + rt.UDP.BytesPerSec,
		PktsPerSec:  rt.TCP.PktsPerSec + rt.UDP.PktsPerSec,
	}

	return RuleMetricsResponse{
		ID:                    id,
		Family:                family,
		Protocol:              protocol,
		LocalPort:             localPort,
		TargetIP:              targetIP,
		TargetPort:            targetPort,
		SampleIntervalSeconds: rt.SampleInterval,
		Cumulative: RuleMetricTotals{
			Total: totalStats,
			TCP:   tcpStats,
			UDP:   udpStats,
		},
		Realtime: RuleMetricRates{
			Total: rt.Total,
			TCP:   rt.TCP,
			UDP:   rt.UDP,
		},
		LastUpdatedUnix: rt.LastUpdatedUnix,
	}
}

func (s *Server) handleRuleDiagnostics(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}

	rule, err := getRuleByIDBasic(r.Context(), s.db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, errors.New("rule not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp, err := diagnoseRule(r.Context(), rule)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	req.Family = normalizeFamily(req.Family)
	req.Protocol = normalizeProtocol(req.Protocol)
	req.Name = strings.TrimSpace(req.Name)
	req.InboundIP = strings.TrimSpace(req.InboundIP)
	req.OutboundIP = strings.TrimSpace(req.OutboundIP)

	if err := validateCreateRuleRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Family == "ipv4" {
		if err := ensureIPv4ForwardEnabled(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	} else {
		if err := ensureIPv6ForwardEnabled(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	id, err := newRuleID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	rule := Rule{
		ID:            id,
		Name:          req.Name,
		Family:        req.Family,
		Protocol:      req.Protocol,
		LocalPort:     req.LocalPort,
		InboundIP:     req.InboundIP,
		TargetIP:      req.TargetIP,
		TargetPort:    req.TargetPort,
		OutboundIP:    req.OutboundIP,
		ConnLimit:     req.ConnLimit,
		BandwidthKbps: req.BandwidthKbps,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer tx.Rollback()

	exists, err := ruleExistsInDBTx(r.Context(), tx, rule.Family, rule.Protocol, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.OutboundIP)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if exists {
		writeError(w, http.StatusConflict, errors.New("rule already exists"))
		return
	}

	portExists, err := localPortExistsInDBTx(r.Context(), tx, rule.LocalPort, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if portExists {
		writeError(w, http.StatusConflict, fmt.Errorf("localPort %d already exists", rule.LocalPort))
		return
	}

	if err := applyRule(r.Context(), s.cfg, rule); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := insertRuleTx(r.Context(), tx, rule); err != nil {
		_ = removeRule(r.Context(), s.cfg, rule)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := saveAfterChange(r.Context(), s.osType, s.cfg, rule.Family); err != nil {
		_ = removeRule(r.Context(), s.cfg, rule)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := tx.Commit(); err != nil {
		_ = removeRule(r.Context(), s.cfg, rule)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusCreated, MessageResponse{Message: "rule created"})
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	var req UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	req.New.Family = normalizeFamily(req.New.Family)
	req.New.Protocol = normalizeProtocol(req.New.Protocol)
	req.New.Name = strings.TrimSpace(req.New.Name)
	req.New.InboundIP = strings.TrimSpace(req.New.InboundIP)
	req.New.OutboundIP = strings.TrimSpace(req.New.OutboundIP)

	if strings.TrimSpace(req.ID) == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if err := validateRuleSpec(req.New); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	oldRule, err := getRuleByIDBasic(r.Context(), s.db, req.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, errors.New("rule not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	newRule := oldRule
	newRule.Name = req.New.Name
	newRule.Family = req.New.Family
	newRule.Protocol = req.New.Protocol
	newRule.LocalPort = req.New.LocalPort
	newRule.InboundIP = req.New.InboundIP
	newRule.TargetIP = req.New.TargetIP
	newRule.TargetPort = req.New.TargetPort
	newRule.OutboundIP = req.New.OutboundIP
	newRule.ConnLimit = req.New.ConnLimit
	newRule.BandwidthKbps = req.New.BandwidthKbps
	newRule.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer tx.Rollback()

	portExists, err := localPortExistsInDBTx(r.Context(), tx, newRule.LocalPort, newRule.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if portExists {
		writeError(w, http.StatusConflict, fmt.Errorf("localPort %d already exists", newRule.LocalPort))
		return
	}

	if err := removeRule(r.Context(), s.cfg, oldRule); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := applyRule(r.Context(), s.cfg, newRule); err != nil {
		_ = applyRule(r.Context(), s.cfg, oldRule)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := updateRuleTx(r.Context(), tx, newRule); err != nil {
		_ = removeRule(r.Context(), s.cfg, newRule)
		_ = applyRule(r.Context(), s.cfg, oldRule)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := saveAfterChange(r.Context(), s.osType, s.cfg, oldRule.Family); err != nil {
		_ = removeRule(r.Context(), s.cfg, newRule)
		_ = applyRule(r.Context(), s.cfg, oldRule)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if newRule.Family != oldRule.Family {
		if err := saveAfterChange(r.Context(), s.osType, s.cfg, newRule.Family); err != nil {
			_ = removeRule(r.Context(), s.cfg, newRule)
			_ = applyRule(r.Context(), s.cfg, oldRule)
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponse{Message: "rule updated"})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	var req DeleteRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}

	rule, err := getRuleByIDBasic(r.Context(), s.db, req.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, errors.New("rule not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer tx.Rollback()

	if err := removeRule(r.Context(), s.cfg, rule); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if _, err := tx.ExecContext(r.Context(), `DELETE FROM rules WHERE id = ?`, rule.ID); err != nil {
		_ = applyRule(r.Context(), s.cfg, rule)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := saveAfterChange(r.Context(), s.osType, s.cfg, rule.Family); err != nil {
		_ = applyRule(r.Context(), s.cfg, rule)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.ruleRealtimeMu.Lock()
	delete(s.ruleRealtime, rule.ID)
	s.ruleRealtimeMu.Unlock()

	writeJSON(w, http.StatusOK, MessageResponse{Message: "rule deleted"})
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	ipf4, _ := isIPv4ForwardEnabled()
	ipf6, _ := isIPv6ForwardEnabled()
	_, err4 := exec.LookPath("iptables")
	_, err6 := exec.LookPath("ip6tables")

	h, err := host.Info()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	parts, err := disk.Partitions(false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var disks []DiskItem
	seen := make(map[string]bool)
	for _, p := range parts {
		if seen[p.Mountpoint] {
			continue
		}
		seen[p.Mountpoint] = true
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		disks = append(disks, DiskItem{
			Device:      p.Device,
			Mountpoint:  p.Mountpoint,
			FSType:      p.Fstype,
			Total:       usage.Total,
			Used:        usage.Used,
			Free:        usage.Free,
			UsedPercent: usage.UsedPercent,
		})
	}

	cpuUsage, cpuModel, cpuReady := s.cpuMonitor.Get()
	interfaces := s.netMonitor.GetAllInterfaces()
	var totalSent, totalRecv uint64
	var totalTx, totalRx uint64
	interval := 1

	for _, n := range interfaces {
		totalSent += n.BytesSent
		totalRecv += n.BytesRecv
		totalTx += n.TxBytesPerSec
		totalRx += n.RxBytesPerSec
		if n.IntervalSeconds > 0 {
			interval = n.IntervalSeconds
		}
	}

	natIPv4, err := natTable(r.Context(), "ipv4")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	natIPv6, err := natTable(r.Context(), "ipv6")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": appVersion,
		"status": StatusResponse{
			OS:             s.osType,
			IPForward4:     ipf4,
			IPForward6:     ipf6,
			HasIptables:    err4 == nil,
			HasIp6tables:   err6 == nil,
			IPv4Masquerade: s.cfg.Firewall.IPv4.EnableMasquerade,
			IPv6Masquerade: s.cfg.Firewall.IPv6.EnableMasquerade,
		},
		"system": SystemInfoResponse{
			Hostname:           h.Hostname,
			OS:                 h.OS,
			Platform:           h.Platform,
			PlatformFamily:     h.PlatformFamily,
			PlatformVersion:    h.PlatformVersion,
			KernelVersion:      h.KernelVersion,
			KernelArch:         h.KernelArch,
			Virtualization:     h.VirtualizationSystem,
			VirtualizationRole: h.VirtualizationRole,
			BootTime:           h.BootTime,
			GoOS:               runtime.GOOS,
			GoArch:             runtime.GOARCH,
			CPUCoresLogical:    runtime.NumCPU(),
		},
		"uptime": UptimeResponse{
			BootTime:       h.BootTime,
			UptimeSeconds:  h.Uptime,
			UptimeReadable: formatUptime(h.Uptime),
		},
		"cpu": CPUResponse{
			ModelName:      cpuModel,
			LogicalCores:   runtime.NumCPU(),
			UsagePercent:   cpuUsage,
			SampleDuration: fmt.Sprintf("%ds", int(s.cpuMonitor.interval.Seconds())),
			Cached:         cpuReady,
		},
		"memory": MemoryResponse{
			Total:       memInfo.Total,
			Available:   memInfo.Available,
			Used:        memInfo.Used,
			UsedPercent: memInfo.UsedPercent,
			Free:        memInfo.Free,
			Cached:      memInfo.Cached,
			Buffers:     memInfo.Buffers,
		},
		"disk": disks,
		"network": map[string]any{
			"interfaces": interfaces,
			"summary": map[string]any{
				"totalBytesSent":      totalSent,
				"totalBytesRecv":      totalRecv,
				"totalBytesSentHuman": bytesToHuman(totalSent),
				"totalBytesRecvHuman": bytesToHuman(totalRecv),
				"intervalSeconds":     interval,
				"totalTxBps":          totalTx,
				"totalRxBps":          totalRx,
				"totalTxHuman":        bytesPerSecToHuman(totalTx),
				"totalRxHuman":        bytesPerSecToHuman(totalRx),
			},
		},
		"nat": map[string]any{
			"ipv4": natIPv4,
			"ipv6": natIPv6,
		},
	})
}

func validateCreateRuleRequest(req CreateRuleRequest) error {
	return validateRuleSpec(RuleSpec{
		Name:          req.Name,
		Family:        req.Family,
		Protocol:      req.Protocol,
		LocalPort:     req.LocalPort,
		InboundIP:     req.InboundIP,
		TargetIP:      req.TargetIP,
		TargetPort:    req.TargetPort,
		OutboundIP:    req.OutboundIP,
		ConnLimit:     req.ConnLimit,
		BandwidthKbps: req.BandwidthKbps,
	})
}

func validateRuleSpec(spec RuleSpec) error {
	spec.Name = strings.TrimSpace(spec.Name)
	spec.InboundIP = strings.TrimSpace(spec.InboundIP)
	spec.OutboundIP = strings.TrimSpace(spec.OutboundIP)
	if len(spec.Name) > 200 {
		return errors.New("name must be <= 200 characters")
	}
	if spec.Family != "ipv4" && spec.Family != "ipv6" {
		return errors.New("family must be ipv4 or ipv6")
	}
	if spec.Protocol != "tcp" && spec.Protocol != "udp" && spec.Protocol != "all" {
		return errors.New("protocol must be tcp, udp, or all")
	}
	if spec.LocalPort < 1 || spec.LocalPort > 65535 {
		return errors.New("localPort must be 1-65535")
	}
	if spec.TargetPort < 1 || spec.TargetPort > 65535 {
		return errors.New("targetPort must be 1-65535")
	}
	if spec.ConnLimit < 0 {
		return errors.New("connLimit must be >= 0")
	}
	if spec.BandwidthKbps < 0 {
		return errors.New("bandwidthKbps must be >= 0")
	}
	ip := net.ParseIP(spec.TargetIP)
	if ip == nil {
		return errors.New("targetIp is invalid")
	}
	if spec.Family == "ipv4" && ip.To4() == nil {
		return errors.New("targetIp must be valid IPv4")
	}
	if spec.Family == "ipv6" && ip.To4() != nil {
		return errors.New("targetIp must be valid IPv6")
	}
	if spec.InboundIP != "" {
		if err := validateRuleBoundIP("inboundIp", spec.InboundIP, spec.Family); err != nil {
			return err
		}
	}
	if spec.OutboundIP != "" {
		if err := validateRuleBoundIP("outboundIp", spec.OutboundIP, spec.Family); err != nil {
			return err
		}
	}
	return nil
}

func validateRuleBoundIP(field, value, family string) error {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return fmt.Errorf("%s is invalid", field)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%s must not be a link-local address", field)
	}
	if family == "ipv4" && ip.To4() == nil {
		return fmt.Errorf("%s must be valid IPv4 for ipv4 rules", field)
	}
	if family == "ipv6" && ip.To4() != nil {
		return fmt.Errorf("%s must be valid IPv6 for ipv6 rules", field)
	}
	return nil
}

func normalizeFamily(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ipv4", "ip4", "4":
		return "ipv4"
	case "ipv6", "ip6", "6":
		return "ipv6"
	case "all":
		return "all"
	default:
		return ""
	}
}

func normalizeProtocol(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	case "both", "all", "":
		return "all"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func expandProtocol(proto string) []string {
	if proto == "all" {
		return []string{"tcp", "udp"}
	}
	return []string{proto}
}

func toolForFamily(family string) string {
	if family == "ipv6" {
		return "ip6tables"
	}
	return "iptables"
}

func saveToolForFamily(family string) string {
	if family == "ipv6" {
		return "ip6tables-save"
	}
	return "iptables-save"
}

func savePathForFamily(cfg Config, family string) string {
	if family == "ipv6" {
		return cfg.Firewall.IPv6.SavePath
	}
	return cfg.Firewall.IPv4.SavePath
}

func enableMasquerade(cfg Config, family string) bool {
	if family == "ipv6" {
		return cfg.Firewall.IPv6.EnableMasquerade
	}
	return cfg.Firewall.IPv4.EnableMasquerade
}

func formatDestination(family, ip string, port int) string {
	if family == "ipv6" {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func connlimitMaskForFamily(family string) string {
	if family == "ipv6" {
		return "128"
	}
	return "32"
}

func appendInboundDestinationMatch(args []string, inboundIP string) []string {
	inboundIP = strings.TrimSpace(inboundIP)
	if inboundIP == "" {
		return args
	}
	return append(args, "-d", inboundIP)
}

func appendConntrackInboundMatch(args []string, inboundIP string, localPort int) []string {
	args = append(args, "-m", "conntrack", "--ctorigdstport", strconv.Itoa(localPort))
	inboundIP = strings.TrimSpace(inboundIP)
	if inboundIP != "" {
		args = append(args, "--ctorigdst", inboundIP)
	}
	return args
}

func newRuleID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func makeComment(ruleID, suffix string) string {
	return ruleTagPrefix + ruleID + ":" + suffix
}

func splitIptablesSaveLine(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	inQuote := false
	escaped := false

	flush := func() {
		if current.Len() == 0 {
			return
		}
		fields = append(fields, current.String())
		current.Reset()
	}

	for _, r := range line {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case !inQuote && (r == ' ' || r == '\t'):
			flush()
		default:
			current.WriteRune(r)
		}
	}

	if escaped || inQuote {
		return nil, fmt.Errorf("invalid iptables-save line: %s", line)
	}
	flush()
	return fields, nil
}

func deleteRulesByComment(ctx context.Context, family, table, chain, comment string) error {
	tool := toolForFamily(family)
	out, err := run(ctx, saveToolForFamily(family))
	if err != nil {
		return err
	}

	var errs []string
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "-A "+chain+" ") {
			continue
		}
		if extractComment(line) != comment {
			continue
		}

		fields, err := splitIptablesSaveLine(line)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if len(fields) < 3 || fields[0] != "-A" || fields[1] != chain {
			continue
		}

		args := append([]string{"-t", table, "-D", chain}, fields[2:]...)
		if _, err := run(ctx, tool, args...); err != nil && !isIgnorableDeleteError(err) {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func cleanupRulesByComments(ctx context.Context, family, table, chain string, comments ...string) error {
	var errs []string
	for _, comment := range comments {
		if strings.TrimSpace(comment) == "" {
			continue
		}
		if err := deleteRulesByComment(ctx, family, table, chain, comment); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func cleanupBandwidthRulesByComment(ctx context.Context, family, proto, ruleID string) error {
	return cleanupRulesByComments(
		ctx,
		family,
		"filter",
		"FORWARD",
		makeComment(ruleID, "bandwidth-"+proto+"-orig"),
		makeComment(ruleID, "bandwidth-"+proto+"-reply"),
		makeComment(ruleID, "bandwidth-"+proto),
	)
}

func cleanupAccountingRulesByComment(ctx context.Context, family, proto, ruleID string) error {
	return cleanupRulesByComments(
		ctx,
		family,
		"filter",
		acctChainName,
		makeComment(ruleID, "acct-"+proto+"-orig"),
		makeComment(ruleID, "acct-"+proto+"-reply"),
		makeComment(ruleID, "acct-"+proto),
	)
}

func addForwardAcceptRules(ctx context.Context, family, proto string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string) error {
	if err := deleteForwardAcceptRules(ctx, family, proto, localPort, inboundIP, targetIP, targetPort, ruleID); err != nil {
		return err
	}

	tool := toolForFamily(family)
	for _, direction := range []string{"ORIGINAL", "REPLY"} {
		args := []string{"-A", "FORWARD", "-p", proto}
		args = appendConntrackInboundMatch(args, inboundIP, localPort)
		args = append(args, "--ctdir", direction)
		if direction == "ORIGINAL" {
			args = append(args, "-d", targetIP, "--dport", strconv.Itoa(targetPort))
			args = append(args, "-m", "comment", "--comment", makeComment(ruleID, "forwardaccept-"+proto+"-orig"))
		} else {
			args = append(args, "-s", targetIP, "--sport", strconv.Itoa(targetPort))
			args = append(args, "-m", "comment", "--comment", makeComment(ruleID, "forwardaccept-"+proto+"-reply"))
		}
		args = append(args, "-j", "ACCEPT")
		if _, err := run(ctx, tool, args...); err != nil {
			return err
		}
	}

	return nil
}

func deleteForwardAcceptRules(ctx context.Context, family, proto string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string) error {
	return cleanupRulesByComments(
		ctx,
		family,
		"filter",
		"FORWARD",
		makeComment(ruleID, "forwardaccept-"+proto+"-orig"),
		makeComment(ruleID, "forwardaccept-"+proto+"-reply"),
	)
}

func addTCPMSSClampRules(ctx context.Context, family string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string) error {
	if err := deleteTCPMSSClampRules(ctx, family, localPort, inboundIP, targetIP, targetPort, ruleID); err != nil {
		return err
	}

	tool := toolForFamily(family)
	for _, direction := range []string{"ORIGINAL", "REPLY"} {
		args := []string{"-t", "mangle", "-I", "FORWARD", "1", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN"}
		args = appendConntrackInboundMatch(args, inboundIP, localPort)
		args = append(args, "--ctdir", direction)
		if direction == "ORIGINAL" {
			args = append(args, "-d", targetIP, "--dport", strconv.Itoa(targetPort))
			args = append(args, "-m", "comment", "--comment", makeComment(ruleID, "mssclamp-tcp-orig"))
		} else {
			args = append(args, "-s", targetIP, "--sport", strconv.Itoa(targetPort))
			args = append(args, "-m", "comment", "--comment", makeComment(ruleID, "mssclamp-tcp-reply"))
		}
		args = append(args, "-j", "TCPMSS", "--clamp-mss-to-pmtu")
		if _, err := run(ctx, tool, args...); err != nil {
			return err
		}
	}

	return nil
}

func deleteTCPMSSClampRules(ctx context.Context, family string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string) error {
	return cleanupRulesByComments(
		ctx,
		family,
		"mangle",
		"FORWARD",
		makeComment(ruleID, "mssclamp-tcp-orig"),
		makeComment(ruleID, "mssclamp-tcp-reply"),
	)
}

func saveAfterChange(ctx context.Context, osType string, cfg Config, family string) error {
	return saveRules(ctx, osType, family, savePathForFamily(cfg, family))
}

func kbpsToBytesPerSec(kbps int) int {
	if kbps <= 0 {
		return 0
	}
	return (kbps * 1000) / 8
}

func hashlimitRateArgFromKbps(kbps int) string {
	bps := kbpsToBytesPerSec(kbps)
	if bps <= 0 {
		return "0b/s"
	}
	return fmt.Sprintf("%db/s", bps)
}

func hashlimitBurstArgFromKbps(kbps int) string {
	bps := kbpsToBytesPerSec(kbps)
	if bps <= 0 {
		return "1b"
	}
	burstBytes := bps * 2
	if burstBytes < 256*1024 {
		burstBytes = 256 * 1024
	}
	return fmt.Sprintf("%db", burstBytes)
}

func bandwidthPayloadMatchArgs(proto string) []string {
	if proto != "tcp" {
		return nil
	}
	return []string{"-m", "length", "--length", fmt.Sprintf("%d:65535", tcpAckMaxLen)}
}

func bandwidthRuleArgs(proto, direction string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string, rateArg string, burstArg string) []string {
	args := []string{"-p", proto}
	args = appendConntrackInboundMatch(args, inboundIP, localPort)
	args = append(args, "--ctdir", direction)

	if direction == "ORIGINAL" {
		args = append(args, "-d", targetIP, "--dport", strconv.Itoa(targetPort))
		args = append(args, "-m", "comment", "--comment", makeComment(ruleID, "bandwidth-"+proto+"-orig"))
		args = append(args, bandwidthPayloadMatchArgs(proto)...)
		args = append(args,
			"-m", "hashlimit",
			"--hashlimit-above", rateArg,
			"--hashlimit-burst", burstArg,
			"--hashlimit-name", "fwapi_bw_"+ruleID+"_"+proto+"_orig",
			"-j", "DROP",
		)
		return args
	}

	args = append(args, "-s", targetIP, "--sport", strconv.Itoa(targetPort))
	args = append(args, "-m", "comment", "--comment", makeComment(ruleID, "bandwidth-"+proto+"-reply"))
	args = append(args, bandwidthPayloadMatchArgs(proto)...)
	args = append(args,
		"-m", "hashlimit",
		"--hashlimit-above", rateArg,
		"--hashlimit-burst", burstArg,
		"--hashlimit-name", "fwapi_bw_"+ruleID+"_"+proto+"_reply",
		"-j", "DROP",
	)
	return args
}

func ensureAcctChain(ctx context.Context, family string) error {
	tool := toolForFamily(family)

	_, err := run(ctx, tool, "-t", "filter", "-N", acctChainName)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "already exists") {
		return err
	}

	_, err = run(ctx, tool, "-t", "filter", "-C", "FORWARD", "-j", acctChainName)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "Bad rule") || strings.Contains(err.Error(), "No chain/target/match") || strings.Contains(err.Error(), "does a matching rule exist") {
		_, err = run(ctx, tool, "-t", "filter", "-I", "FORWARD", "1", "-j", acctChainName)
		return err
	}
	return err
}

func addAccountingRules(ctx context.Context, family, proto string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string) error {
	if err := cleanupAccountingRulesByComment(ctx, family, proto, ruleID); err != nil {
		return err
	}
	tool := toolForFamily(family)

	args := []string{"-t", "filter", "-A", acctChainName, "-p", proto}
	args = appendConntrackInboundMatch(args, inboundIP, localPort)
	args = append(args, "--ctdir", "ORIGINAL",
		"-d", targetIP, "--dport", strconv.Itoa(targetPort),
		"-m", "comment", "--comment", makeComment(ruleID, "acct-"+proto+"-orig"),
		"-j", "RETURN")
	_, err := run(ctx, tool, args...)
	if err != nil {
		return err
	}

	args = []string{"-t", "filter", "-A", acctChainName, "-p", proto}
	args = appendConntrackInboundMatch(args, inboundIP, localPort)
	args = append(args, "--ctdir", "REPLY",
		"-s", targetIP, "--sport", strconv.Itoa(targetPort),
		"-m", "comment", "--comment", makeComment(ruleID, "acct-"+proto+"-reply"),
		"-j", "RETURN")
	_, err = run(ctx, tool, args...)
	return err
}

func deleteAccountingRules(ctx context.Context, family, proto string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string) error {
	return cleanupAccountingRulesByComment(ctx, family, proto, ruleID)
}

func addBandwidthRules(ctx context.Context, family, proto string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string, kbps int) error {
	if kbps <= 0 {
		return nil
	}
	if err := cleanupBandwidthRulesByComment(ctx, family, proto, ruleID); err != nil {
		return err
	}
	tool := toolForFamily(family)
	rateArg := hashlimitRateArgFromKbps(kbps)
	burstArg := hashlimitBurstArgFromKbps(kbps)

	_, err := run(ctx, tool, append([]string{"-I", "FORWARD", "1"}, bandwidthRuleArgs(proto, "ORIGINAL", localPort, inboundIP, targetIP, targetPort, ruleID, rateArg, burstArg)...)...)
	if err != nil {
		return err
	}

	_, err = run(ctx, tool, append([]string{"-I", "FORWARD", "1"}, bandwidthRuleArgs(proto, "REPLY", localPort, inboundIP, targetIP, targetPort, ruleID, rateArg, burstArg)...)...)
	return err
}

func deleteBandwidthRules(ctx context.Context, family, proto string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string, kbps int) error {
	return cleanupBandwidthRulesByComment(ctx, family, proto, ruleID)
}

func addConnLimitRules(ctx context.Context, family, proto string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string, connLimit int) error {
	if connLimit <= 0 {
		return nil
	}
	tool := toolForFamily(family)

	if proto == "tcp" {
		args := []string{"-I", "FORWARD", "1", "-p", "tcp", "--syn", "-d", targetIP, "--dport", strconv.Itoa(targetPort)}
		args = appendConntrackInboundMatch(args, inboundIP, localPort)
		args = append(args, "--ctstate", "NEW",
			"-m", "comment", "--comment", makeComment(ruleID, "connlimit-tcp"),
			"-m", "connlimit",
			"--connlimit-above", strconv.Itoa(connLimit),
			"--connlimit-mask", connlimitMaskForFamily(family),
			"--connlimit-saddr",
			"-j", "DROP")
		_, err := run(ctx, tool, args...)
		return err
	}

	args := []string{"-I", "FORWARD", "1", "-p", proto, "-d", targetIP, "--dport", strconv.Itoa(targetPort)}
	args = appendConntrackInboundMatch(args, inboundIP, localPort)
	args = append(args, "--ctstate", "NEW",
		"-m", "comment", "--comment", makeComment(ruleID, "connlimit-"+proto),
		"-m", "connlimit",
		"--connlimit-above", strconv.Itoa(connLimit),
		"--connlimit-mask", connlimitMaskForFamily(family),
		"--connlimit-saddr",
		"-j", "DROP")
	_, err := run(ctx, tool, args...)
	return err
}

func deleteConnLimitRules(ctx context.Context, family, proto string, localPort int, inboundIP, targetIP string, targetPort int, ruleID string, connLimit int) error {
	if connLimit <= 0 {
		return nil
	}
	tool := toolForFamily(family)
	var errs []string

	if proto == "tcp" {
		args := []string{"-D", "FORWARD", "-p", "tcp", "--syn", "-d", targetIP, "--dport", strconv.Itoa(targetPort)}
		args = appendConntrackInboundMatch(args, inboundIP, localPort)
		args = append(args, "--ctstate", "NEW",
			"-m", "comment", "--comment", makeComment(ruleID, "connlimit-tcp"),
			"-m", "connlimit",
			"--connlimit-above", strconv.Itoa(connLimit),
			"--connlimit-mask", connlimitMaskForFamily(family),
			"--connlimit-saddr",
			"-j", "DROP")
		_, err := run(ctx, tool, args...)
		if err != nil && !isIgnorableDeleteError(err) {
			errs = append(errs, err.Error())
		}
	} else {
		args := []string{"-D", "FORWARD", "-p", proto, "-d", targetIP, "--dport", strconv.Itoa(targetPort)}
		args = appendConntrackInboundMatch(args, inboundIP, localPort)
		args = append(args, "--ctstate", "NEW",
			"-m", "comment", "--comment", makeComment(ruleID, "connlimit-"+proto),
			"-m", "connlimit",
			"--connlimit-above", strconv.Itoa(connLimit),
			"--connlimit-mask", connlimitMaskForFamily(family),
			"--connlimit-saddr",
			"-j", "DROP")
		_, err := run(ctx, tool, args...)
		if err != nil && !isIgnorableDeleteError(err) {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func applyRule(ctx context.Context, cfg Config, rule Rule) error {
	protos := expandProtocol(rule.Protocol)

	if err := setForwardPolicy(ctx, rule.Family, cfg.Firewall.DefaultForwardPolicy); err != nil {
		return err
	}
	if err := ensureAcctChain(ctx, rule.Family); err != nil {
		return err
	}

	for _, proto := range protos {
		dest := formatDestination(rule.Family, rule.TargetIP, rule.TargetPort)
		args := []string{"-t", "nat", "-A", "PREROUTING", "-p", proto}
		args = appendInboundDestinationMatch(args, rule.InboundIP)
		args = append(args,
			"--dport", strconv.Itoa(rule.LocalPort),
			"-m", "comment", "--comment", makeComment(rule.ID, "dnat-"+proto),
			"-j", "DNAT",
			"--to-destination", dest)

		if _, err := run(ctx, toolForFamily(rule.Family), args...); err != nil {
			_ = removeRule(ctx, cfg, rule)
			return err
		}

		if rule.OutboundIP != "" {
			if _, err := run(ctx, toolForFamily(rule.Family),
				"-t", "nat", "-A", "POSTROUTING",
				"-p", proto,
				"-d", rule.TargetIP,
				"--dport", strconv.Itoa(rule.TargetPort),
				"-m", "comment", "--comment", makeComment(rule.ID, "snat-"+proto),
				"-j", "SNAT",
				"--to-source", rule.OutboundIP,
			); err != nil {
				_ = removeRule(ctx, cfg, rule)
				return err
			}
		} else if enableMasquerade(cfg, rule.Family) {
			if _, err := run(ctx, toolForFamily(rule.Family),
				"-t", "nat", "-A", "POSTROUTING",
				"-p", proto,
				"-d", rule.TargetIP,
				"--dport", strconv.Itoa(rule.TargetPort),
				"-m", "comment", "--comment", makeComment(rule.ID, "masq-"+proto),
				"-j", "MASQUERADE",
			); err != nil {
				_ = removeRule(ctx, cfg, rule)
				return err
			}
		}

		if proto == "tcp" {
			if err := addTCPMSSClampRules(ctx, rule.Family, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID); err != nil {
				_ = removeRule(ctx, cfg, rule)
				return err
			}
		}

		if err := addForwardAcceptRules(ctx, rule.Family, proto, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID); err != nil {
			_ = removeRule(ctx, cfg, rule)
			return err
		}

		if err := addAccountingRules(ctx, rule.Family, proto, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID); err != nil {
			_ = removeRule(ctx, cfg, rule)
			return err
		}

		if err := addConnLimitRules(ctx, rule.Family, proto, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID, rule.ConnLimit); err != nil {
			_ = removeRule(ctx, cfg, rule)
			return err
		}

		if err := addBandwidthRules(ctx, rule.Family, proto, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID, rule.BandwidthKbps); err != nil {
			_ = removeRule(ctx, cfg, rule)
			return err
		}
	}

	return nil
}

func removeRule(ctx context.Context, cfg Config, rule Rule) error {
	var errs []string
	protos := expandProtocol(rule.Protocol)
	tool := toolForFamily(rule.Family)

	for _, proto := range protos {
		if proto == "tcp" {
			if err := deleteTCPMSSClampRules(ctx, rule.Family, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID); err != nil {
				errs = append(errs, err.Error())
			}
		}

		if err := deleteForwardAcceptRules(ctx, rule.Family, proto, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID); err != nil {
			errs = append(errs, err.Error())
		}

		if err := deleteBandwidthRules(ctx, rule.Family, proto, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID, rule.BandwidthKbps); err != nil {
			errs = append(errs, err.Error())
		}

		if err := deleteConnLimitRules(ctx, rule.Family, proto, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID, rule.ConnLimit); err != nil {
			errs = append(errs, err.Error())
		}

		if err := deleteAccountingRules(ctx, rule.Family, proto, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.ID); err != nil {
			errs = append(errs, err.Error())
		}

		if rule.OutboundIP != "" {
			_, err := run(ctx, tool,
				"-t", "nat", "-D", "POSTROUTING",
				"-p", proto,
				"-d", rule.TargetIP,
				"--dport", strconv.Itoa(rule.TargetPort),
				"-m", "comment", "--comment", makeComment(rule.ID, "snat-"+proto),
				"-j", "SNAT",
				"--to-source", rule.OutboundIP,
			)
			if err != nil && !isIgnorableDeleteError(err) {
				errs = append(errs, err.Error())
			}
		} else if enableMasquerade(cfg, rule.Family) {
			_, err := run(ctx, tool,
				"-t", "nat", "-D", "POSTROUTING",
				"-p", proto,
				"-d", rule.TargetIP,
				"--dport", strconv.Itoa(rule.TargetPort),
				"-m", "comment", "--comment", makeComment(rule.ID, "masq-"+proto),
				"-j", "MASQUERADE",
			)
			if err != nil && !isIgnorableDeleteError(err) {
				errs = append(errs, err.Error())
			}
		}

		dest := formatDestination(rule.Family, rule.TargetIP, rule.TargetPort)
		args := []string{"-t", "nat", "-D", "PREROUTING", "-p", proto}
		args = appendInboundDestinationMatch(args, rule.InboundIP)
		args = append(args,
			"--dport", strconv.Itoa(rule.LocalPort),
			"-m", "comment", "--comment", makeComment(rule.ID, "dnat-"+proto),
			"-j", "DNAT",
			"--to-destination", dest)
		_, err := run(ctx, tool, args...)
		if err != nil && !isIgnorableDeleteError(err) {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func isIgnorableDeleteError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Bad rule") ||
		strings.Contains(msg, "No chain/target/match") ||
		strings.Contains(msg, "does a matching rule exist")
}

func setForwardPolicy(ctx context.Context, family, policy string) error {
	policy = strings.ToUpper(strings.TrimSpace(policy))
	if policy == "" {
		policy = "ACCEPT"
	}
	_, err := run(ctx, toolForFamily(family), "-P", "FORWARD", policy)
	return err
}

func natTable(ctx context.Context, family string) (string, error) {
	return run(ctx, toolForFamily(family), "-t", "nat", "-L", "-n", "-v", "--line-numbers")
}

func saveRules(ctx context.Context, osType, family, savePath string) error {
	out, err := run(ctx, saveToolForFamily(family), "-c")
	if err != nil {
		return err
	}

	switch osType {
	case "debian":
		dir := filepath.Dir(savePath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(savePath, []byte(out+"\n"), 0o600); err != nil {
			return err
		}
		if _, err := exec.LookPath("netfilter-persistent"); err == nil {
			if _, err := run(ctx, "netfilter-persistent", "save"); err != nil {
				return err
			}
		}
		return nil

	case "centos":
		dir := filepath.Dir(savePath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(savePath, []byte(out+"\n"), 0o600); err != nil {
			return err
		}
		if _, err := exec.LookPath("service"); err == nil {
			if family == "ipv4" {
				if _, err := run(ctx, "service", "iptables", "save"); err == nil {
					return nil
				}
			} else {
				if _, err := run(ctx, "service", "ip6tables", "save"); err == nil {
					return nil
				}
			}
		}
		return nil

	default:
		return errors.New("unsupported os for save")
	}
}

func ensureIPv4ForwardEnabled(ctx context.Context) error {
	enabled, _ := isIPv4ForwardEnabled()
	if enabled {
		return nil
	}
	if err := appendSysctlIfMissing("net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	_, err := run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1")
	return err
}

func ensureIPv6ForwardEnabled(ctx context.Context) error {
	enabled, _ := isIPv6ForwardEnabled()
	if enabled {
		return nil
	}
	if err := appendSysctlIfMissing("net.ipv6.conf.all.forwarding=1"); err != nil {
		return err
	}
	_, err := run(ctx, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	return err
}

func isIPv4ForwardEnabled() (bool, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(b)) == "1", nil
}

func isIPv6ForwardEnabled() (bool, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(b)) == "1", nil
}

func appendSysctlIfMissing(line string) error {
	b, _ := os.ReadFile("/etc/sysctl.conf")
	content := string(b)
	if strings.Contains(content, line) {
		return nil
	}

	f, err := os.OpenFile("/etc/sysctl.conf", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString("\n" + line + "\n")
	return err
}

func run(parent context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))

	if ctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("command timeout: %s %s", name, strings.Join(args, " "))
	}
	if err != nil {
		if text == "" {
			return text, fmt.Errorf("command failed: %s %s: %w", name, strings.Join(args, " "), err)
		}
		return text, fmt.Errorf("command failed: %s %s: %s", name, strings.Join(args, " "), text)
	}
	return text, nil
}

func diagnoseRule(ctx context.Context, rule Rule) (RuleDiagnosticResponse, error) {
	effectiveOutboundIP, err := resolveEffectiveOutboundIP(rule)
	if err != nil {
		return RuleDiagnosticResponse{}, err
	}

	method := "tcp-connect"
	latencyMs := 0.0
	successfulSamples := 0
	const sampleCount = 3

	if rule.Protocol == "udp" {
		method = "icmp-ping"
		latencyMs, successfulSamples, err = measureICMPLatency(ctx, rule.Family, rule.TargetIP, rule.OutboundIP, sampleCount)
	} else {
		latencyMs, successfulSamples, err = measureTCPConnectLatency(ctx, rule.Family, rule.TargetIP, rule.TargetPort, rule.OutboundIP, sampleCount)
	}
	if err != nil {
		return RuleDiagnosticResponse{}, err
	}

	return RuleDiagnosticResponse{
		ID:                   rule.ID,
		Family:               rule.Family,
		Protocol:             rule.Protocol,
		TargetIP:             rule.TargetIP,
		TargetPort:           rule.TargetPort,
		ConfiguredOutboundIP: rule.OutboundIP,
		EffectiveOutboundIP:  effectiveOutboundIP,
		Method:               method,
		SampleCount:          sampleCount,
		SuccessfulSamples:    successfulSamples,
		LatencyMs:            latencyMs,
		DiagnosedAt:          time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func resolveEffectiveOutboundIP(rule Rule) (string, error) {
	if rule.OutboundIP != "" {
		return rule.OutboundIP, nil
	}

	network := "udp4"
	if rule.Family == "ipv6" {
		network = "udp6"
	}

	conn, err := net.Dial(network, net.JoinHostPort(rule.TargetIP, strconv.Itoa(rule.TargetPort)))
	if err != nil {
		return "", fmt.Errorf("resolve outbound ip failed: %w", err)
	}
	defer conn.Close()

	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.String(), nil
	}
	return "", errors.New("resolve outbound ip failed: no local address")
}

func measureTCPConnectLatency(ctx context.Context, family, targetIP string, targetPort int, outboundIP string, sampleCount int) (float64, int, error) {
	network := "tcp4"
	if family == "ipv6" {
		network = "tcp6"
	}

	address := net.JoinHostPort(targetIP, strconv.Itoa(targetPort))
	totalMs := 0.0
	successfulSamples := 0

	for i := 0; i < sampleCount; i++ {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		if outboundIP != "" {
			localIP := net.ParseIP(outboundIP)
			if localIP == nil {
				return 0, 0, errors.New("configured outbound ip is invalid")
			}
			dialer.LocalAddr = &net.TCPAddr{IP: localIP}
		}

		startedAt := time.Now()
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			continue
		}
		totalMs += float64(time.Since(startedAt).Microseconds()) / 1000
		successfulSamples++
		_ = conn.Close()
	}

	if successfulSamples == 0 {
		return 0, 0, fmt.Errorf("tcp diagnostic failed: target %s is unreachable", address)
	}
	return totalMs / float64(successfulSamples), successfulSamples, nil
}

func measureICMPLatency(parent context.Context, family, targetIP, outboundIP string, sampleCount int) (float64, int, error) {
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()

	args := []string{"-n", "-q", "-c", strconv.Itoa(sampleCount), "-W", "1"}
	if family == "ipv6" {
		args = append(args, "-6")
	}
	if outboundIP != "" {
		args = append(args, "-I", outboundIP)
	}
	args = append(args, targetIP)

	cmd := exec.CommandContext(ctx, "ping", args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return 0, 0, fmt.Errorf("icmp diagnostic timeout: %s", targetIP)
	}

	recvMatch := pingRecvRe.FindStringSubmatch(text)
	statsMatch := pingStatsRe.FindStringSubmatch(text)
	if err != nil && len(statsMatch) == 0 {
		if text == "" {
			return 0, 0, fmt.Errorf("icmp diagnostic failed: %w", err)
		}
		return 0, 0, fmt.Errorf("icmp diagnostic failed: %s", text)
	}
	if len(statsMatch) < 3 {
		return 0, 0, fmt.Errorf("icmp diagnostic failed: no latency data for %s", targetIP)
	}

	avgLatency, parseErr := strconv.ParseFloat(statsMatch[2], 64)
	if parseErr != nil {
		return 0, 0, fmt.Errorf("icmp diagnostic parse failed: %w", parseErr)
	}

	successfulSamples := sampleCount
	if len(recvMatch) == 3 {
		if recvVal, recvErr := strconv.Atoi(recvMatch[2]); recvErr == nil {
			successfulSamples = recvVal
		}
	}

	if successfulSamples == 0 {
		return 0, 0, fmt.Errorf("icmp diagnostic failed: target %s is unreachable", targetIP)
	}

	return avgLatency, successfulSamples, nil
}

func insertRuleTx(ctx context.Context, tx *sql.Tx, rule Rule) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO rules (
	id, name, family, protocol, local_port, inbound_ip, target_ip, target_port, outbound_ip,
	conn_limit, bandwidth_kbps, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.Name, rule.Family, rule.Protocol, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.OutboundIP,
		rule.ConnLimit, rule.BandwidthKbps, boolToInt(rule.Enabled), rule.CreatedAt, rule.UpdatedAt,
	)
	if err != nil {
		return err
	}

	for _, proto := range []string{"tcp", "udp"} {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO rule_counters (
	rule_id, protocol, total_packets, total_bytes, last_kernel_packets, last_kernel_bytes, updated_at
) VALUES (?, ?, 0, 0, 0, 0, ?)`,
			rule.ID, proto, rule.UpdatedAt,
		); err != nil {
			return err
		}
	}
	return nil
}

func updateRuleTx(ctx context.Context, tx *sql.Tx, rule Rule) error {
	_, err := tx.ExecContext(ctx, `
UPDATE rules SET
	name = ?, family = ?, protocol = ?, local_port = ?, inbound_ip = ?, target_ip = ?, target_port = ?, outbound_ip = ?,
	conn_limit = ?, bandwidth_kbps = ?, updated_at = ?
WHERE id = ?`,
		rule.Name, rule.Family, rule.Protocol, rule.LocalPort, rule.InboundIP, rule.TargetIP, rule.TargetPort, rule.OutboundIP,
		rule.ConnLimit, rule.BandwidthKbps, rule.UpdatedAt, rule.ID,
	)
	return err
}

func ruleExistsInDBTx(ctx context.Context, tx *sql.Tx, family, protocol string, localPort int, inboundIP, targetIP string, targetPort int, outboundIP string) (bool, error) {
	row := tx.QueryRowContext(ctx, `
SELECT COUNT(1) FROM rules
WHERE family = ? AND protocol = ? AND local_port = ? AND inbound_ip = ? AND target_ip = ? AND target_port = ? AND outbound_ip = ?`,
		family, protocol, localPort, inboundIP, targetIP, targetPort, outboundIP,
	)
	var n int
	if err := row.Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func localPortExistsInDBTx(ctx context.Context, tx *sql.Tx, localPort int, excludeID string) (bool, error) {
	query := `SELECT COUNT(1) FROM rules WHERE local_port = ?`
	args := []any{localPort}
	if excludeID != "" {
		query += ` AND id <> ?`
		args = append(args, excludeID)
	}
	row := tx.QueryRowContext(ctx, query, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func getRuleByIDBasic(ctx context.Context, db *sql.DB, id string) (Rule, error) {
	row := db.QueryRowContext(ctx, `
SELECT
	id, name, family, protocol, local_port, inbound_ip, target_ip, target_port, outbound_ip,
	conn_limit, bandwidth_kbps, enabled, created_at, updated_at
FROM rules
WHERE id = ?`, id)

	var rule Rule
	var enabled int
	err := row.Scan(
		&rule.ID, &rule.Name, &rule.Family, &rule.Protocol, &rule.LocalPort, &rule.InboundIP, &rule.TargetIP, &rule.TargetPort, &rule.OutboundIP,
		&rule.ConnLimit, &rule.BandwidthKbps, &enabled, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return rule, err
	}
	rule.Enabled = enabled == 1
	return rule, nil
}

func getRuleProtocolStats(ctx context.Context, db *sql.DB, id string) (ProtocolStats, ProtocolStats, error) {
	rows, err := db.QueryContext(ctx, `
SELECT protocol, total_bytes, total_packets
FROM rule_counters
WHERE rule_id = ?`, id)
	if err != nil {
		return ProtocolStats{}, ProtocolStats{}, err
	}
	defer rows.Close()

	var tcpStats ProtocolStats
	var udpStats ProtocolStats

	for rows.Next() {
		var proto string
		var bytesVal uint64
		var pktsVal uint64

		if err := rows.Scan(&proto, &bytesVal, &pktsVal); err != nil {
			return ProtocolStats{}, ProtocolStats{}, err
		}

		switch proto {
		case "tcp":
			tcpStats = ProtocolStats{TrafficBytes: bytesVal, TrafficPkts: pktsVal}
		case "udp":
			udpStats = ProtocolStats{TrafficBytes: bytesVal, TrafficPkts: pktsVal}
		}
	}

	return tcpStats, udpStats, rows.Err()
}

func listRulesFromDB(ctx context.Context, db *sql.DB, family string) ([]RuleListItem, error) {
	query := `
SELECT
	r.id, r.name, r.family, r.protocol, r.local_port, r.inbound_ip, r.target_ip, r.target_port, r.outbound_ip,
	r.conn_limit, r.bandwidth_kbps, r.enabled, r.created_at, r.updated_at,
	COALESCE(tc.total_bytes, 0), COALESCE(tc.total_packets, 0),
	COALESCE(uc.total_bytes, 0), COALESCE(uc.total_packets, 0)
FROM rules r
LEFT JOIN rule_counters tc ON tc.rule_id = r.id AND tc.protocol = 'tcp'
LEFT JOIN rule_counters uc ON uc.rule_id = r.id AND uc.protocol = 'udp'
	`
	args := []any{}
	if family != "" {
		query += "WHERE r.family = ?\n"
		args = append(args, family)
	}
	query += "ORDER BY r.created_at DESC"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []RuleListItem
	for rows.Next() {
		var item RuleListItem
		var enabled int
		if err := rows.Scan(
			&item.ID, &item.Name, &item.Family, &item.Protocol, &item.LocalPort, &item.InboundIP, &item.TargetIP, &item.TargetPort, &item.OutboundIP,
			&item.ConnLimit, &item.BandwidthKbps, &enabled, &item.CreatedAt, &item.UpdatedAt,
			&item.TCP.TrafficBytes, &item.TCP.TrafficPkts,
			&item.UDP.TrafficBytes, &item.UDP.TrafficPkts,
		); err != nil {
			return nil, err
		}
		item.Enabled = enabled == 1
		item.Total = ProtocolStats{
			TrafficBytes: item.TCP.TrafficBytes + item.UDP.TrafficBytes,
			TrafficPkts:  item.TCP.TrafficPkts + item.UDP.TrafficPkts,
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Server) startStatsSyncLoop() {
	ticker := time.NewTicker(time.Duration(s.cfg.Monitor.StatsPollSeconds) * time.Second)
	defer ticker.Stop()

	for {
		s.syncRuleCounters(context.Background())
		<-ticker.C
	}
}

func (s *Server) syncRuleCounters(ctx context.Context) {
	deltas := make(map[string]map[string]ProtocolStats)

	if d, err := syncFamilyCounters(ctx, s.db, "ipv4"); err != nil {
		log.Printf("sync ipv4 counters failed: %v", err)
	} else {
		mergeDeltaStats(deltas, d)
	}

	if d, err := syncFamilyCounters(ctx, s.db, "ipv6"); err != nil {
		log.Printf("sync ipv6 counters failed: %v", err)
	} else {
		mergeDeltaStats(deltas, d)
	}

	if len(deltas) == 0 {
		return
	}

	s.ruleRealtimeMu.Lock()
	defer s.ruleRealtimeMu.Unlock()

	for ruleID, byProto := range deltas {
		rt := s.ruleRealtime[ruleID]
		rt.SampleInterval = s.cfg.Monitor.StatsPollSeconds
		rt.LastUpdatedUnix = time.Now().Unix()

		if tcp, ok := byProto["tcp"]; ok {
			rt.TCP = ProtocolRealtime{
				BytesPerSec: tcp.TrafficBytes / uint64(maxInt(1, s.cfg.Monitor.StatsPollSeconds)),
				PktsPerSec:  tcp.TrafficPkts / uint64(maxInt(1, s.cfg.Monitor.StatsPollSeconds)),
			}
		} else {
			rt.TCP = ProtocolRealtime{}
		}

		if udp, ok := byProto["udp"]; ok {
			rt.UDP = ProtocolRealtime{
				BytesPerSec: udp.TrafficBytes / uint64(maxInt(1, s.cfg.Monitor.StatsPollSeconds)),
				PktsPerSec:  udp.TrafficPkts / uint64(maxInt(1, s.cfg.Monitor.StatsPollSeconds)),
			}
		} else {
			rt.UDP = ProtocolRealtime{}
		}

		rt.Total = ProtocolRealtime{
			BytesPerSec: rt.TCP.BytesPerSec + rt.UDP.BytesPerSec,
			PktsPerSec:  rt.TCP.PktsPerSec + rt.UDP.PktsPerSec,
		}
		s.ruleRealtime[ruleID] = rt
	}
}

func mergeDeltaStats(dst map[string]map[string]ProtocolStats, src map[string]map[string]ProtocolStats) {
	for ruleID, byProto := range src {
		if _, ok := dst[ruleID]; !ok {
			dst[ruleID] = make(map[string]ProtocolStats)
		}
		for proto, stats := range byProto {
			cur := dst[ruleID][proto]
			cur.TrafficBytes += stats.TrafficBytes
			cur.TrafficPkts += stats.TrafficPkts
			dst[ruleID][proto] = cur
		}
	}
}

func syncFamilyCounters(ctx context.Context, db *sql.DB, family string) (map[string]map[string]ProtocolStats, error) {
	out, err := run(ctx, saveToolForFamily(family), "-c")
	if err != nil {
		return nil, err
	}

	counters := parseAccountingCounters(out)
	if len(counters) == 0 {
		return map[string]map[string]ProtocolStats{}, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	deltas := make(map[string]map[string]ProtocolStats)

	for _, rec := range counters {
		row := tx.QueryRowContext(ctx, `
SELECT total_packets, total_bytes, last_kernel_packets, last_kernel_bytes
FROM rule_counters
WHERE rule_id = ? AND protocol = ?`,
			rec.RuleID, rec.Protocol,
		)

		var totalPkts, totalBytes, lastPkts, lastBytes uint64
		err := row.Scan(&totalPkts, &totalBytes, &lastPkts, &lastBytes)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, err
		}

		var deltaPkts, deltaBytes uint64
		if rec.Pkts >= lastPkts {
			deltaPkts = rec.Pkts - lastPkts
		} else {
			deltaPkts = rec.Pkts
		}
		if rec.Bytes >= lastBytes {
			deltaBytes = rec.Bytes - lastBytes
		} else {
			deltaBytes = rec.Bytes
		}

		totalPkts += deltaPkts
		totalBytes += deltaBytes

		_, err = tx.ExecContext(ctx, `
UPDATE rule_counters
SET total_packets = ?, total_bytes = ?, last_kernel_packets = ?, last_kernel_bytes = ?, updated_at = ?
WHERE rule_id = ? AND protocol = ?`,
			totalPkts, totalBytes, rec.Pkts, rec.Bytes, now, rec.RuleID, rec.Protocol,
		)
		if err != nil {
			return nil, err
		}

		if _, ok := deltas[rec.RuleID]; !ok {
			deltas[rec.RuleID] = make(map[string]ProtocolStats)
		}
		cur := deltas[rec.RuleID][rec.Protocol]
		cur.TrafficBytes += deltaBytes
		cur.TrafficPkts += deltaPkts
		deltas[rec.RuleID][rec.Protocol] = cur
	}

	return deltas, tx.Commit()
}

func parseAccountingCounters(text string) map[string]counterRecord {
	out := make(map[string]counterRecord)
	sc := bufio.NewScanner(strings.NewReader(text))
	inFilter := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "*filter" {
			inFilter = true
			continue
		}
		if strings.HasPrefix(line, "*") && line != "*filter" {
			inFilter = false
			continue
		}
		if !inFilter {
			continue
		}
		if !strings.Contains(line, "-A "+acctChainName) {
			continue
		}
		if !strings.Contains(line, "--comment") {
			continue
		}

		m := saveCounterRe.FindStringSubmatch(line)
		if len(m) != 4 {
			continue
		}

		pkts, _ := strconv.ParseUint(m[1], 10, 64)
		bytesVal, _ := strconv.ParseUint(m[2], 10, 64)

		comment := extractComment(line)
		if comment == "" || !strings.HasPrefix(comment, ruleTagPrefix) {
			continue
		}

		ruleID, proto := parseRuleIDAndProtoFromComment(comment)
		if ruleID == "" || proto == "" {
			continue
		}

		key := ruleID + ":" + proto
		rec := out[key]
		rec.RuleID = ruleID
		rec.Protocol = proto
		rec.Pkts += pkts
		rec.Bytes += bytesVal
		out[key] = rec
	}

	return out
}

func extractComment(line string) string {
	if m := commentQuoted.FindStringSubmatch(line); len(m) == 2 {
		return m[1]
	}
	if m := commentBare.FindStringSubmatch(line); len(m) == 2 {
		return strings.Trim(m[1], `"`)
	}
	return ""
}

func parseRuleIDAndProtoFromComment(comment string) (string, string) {
	if !strings.HasPrefix(comment, ruleTagPrefix) {
		return "", ""
	}
	x := strings.TrimPrefix(comment, ruleTagPrefix)
	parts := strings.SplitN(x, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	ruleID := parts[0]
	suffix := parts[1]

	switch {
	case strings.HasPrefix(suffix, "acct-tcp-"):
		return ruleID, "tcp"
	case suffix == "acct-tcp":
		return ruleID, "tcp"
	case strings.HasPrefix(suffix, "acct-udp-"):
		return ruleID, "udp"
	case suffix == "acct-udp":
		return ruleID, "udp"
	default:
		return "", ""
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, APIError{Error: err.Error()})
}

func formatUptime(seconds uint64) string {
	d := time.Duration(seconds) * time.Second
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	secs := d / time.Second

	parts := make([]string, 0, 4)
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	parts = append(parts,
		fmt.Sprintf("%dh", hours),
		fmt.Sprintf("%dm", minutes),
		fmt.Sprintf("%ds", secs),
	)
	return strings.Join(parts, " ")
}

func isIgnoredNIC(name string) bool {
	prefixes := []string{"lo", "docker", "veth", "br-", "virbr", "vmnet", "zt", "tailscale", "tun", "tap"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func bytesToHuman(b uint64) string {
	const unit = 1024
	if b < unit {
		return strconv.FormatUint(b, 10) + " B"
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return strconv.FormatFloat(float64(b)/float64(div), 'f', 2, 64) + " " + units[exp]
}

func bytesPerSecToHuman(bps uint64) string {
	return bytesToHuman(bps) + "/s"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func NewNetworkMonitor(interval time.Duration) *NetworkMonitor {
	if interval <= 0 {
		interval = time.Second
	}
	return &NetworkMonitor{
		interval: interval,
		lastRaw:  make(map[string]NetSnapshot),
		stats:    make(map[string]NetSnapshot),
		rate:     make(map[string]NetRealtime),
	}
}

func (m *NetworkMonitor) Start() {
	go func() {
		_ = m.collect()
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for range ticker.C {
			_ = m.collect()
		}
	}()
}

func (m *NetworkMonitor) collect() error {
	counters, err := netio.IOCounters(true)
	if err != nil {
		return err
	}

	current := make(map[string]NetSnapshot)
	for _, n := range counters {
		if isIgnoredNIC(n.Name) {
			continue
		}
		current[n.Name] = NetSnapshot{
			Name:        n.Name,
			BytesSent:   n.BytesSent,
			BytesRecv:   n.BytesRecv,
			PacketsSent: n.PacketsSent,
			PacketsRecv: n.PacketsRecv,
			Errin:       n.Errin,
			Errout:      n.Errout,
			Dropin:      n.Dropin,
			Dropout:     n.Dropout,
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	intervalSec := int(m.interval.Seconds())
	if intervalSec <= 0 {
		intervalSec = 1
	}

	if !m.lastAt.IsZero() {
		for name, cur := range current {
			prev, ok := m.lastRaw[name]
			if !ok {
				continue
			}

			var txDelta, rxDelta uint64
			if cur.BytesSent >= prev.BytesSent {
				txDelta = cur.BytesSent - prev.BytesSent
			}
			if cur.BytesRecv >= prev.BytesRecv {
				rxDelta = cur.BytesRecv - prev.BytesRecv
			}

			m.rate[name] = NetRealtime{
				Name:            name,
				IntervalSeconds: intervalSec,
				TxBytesPerSec:   txDelta / uint64(intervalSec),
				RxBytesPerSec:   rxDelta / uint64(intervalSec),
				TxHuman:         bytesPerSecToHuman(txDelta / uint64(intervalSec)),
				RxHuman:         bytesPerSecToHuman(rxDelta / uint64(intervalSec)),
			}
		}
	}

	m.stats = current
	m.lastRaw = current
	m.lastAt = time.Now()
	return nil
}

func (m *NetworkMonitor) GetAllInterfaces() []NetInterfaceData {
	m.mu.RLock()
	defer m.mu.RUnlock()

	addressMap := readInterfaceAddressMap()

	names := make([]string, 0, len(m.stats)+len(addressMap))
	seen := make(map[string]bool)
	for name := range m.stats {
		seen[name] = true
		names = append(names, name)
	}
	for name := range addressMap {
		if seen[name] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]NetInterfaceData, 0, len(names))
	for _, name := range names {
		s := m.stats[name]
		r := m.rate[name]
		result = append(result, NetInterfaceData{
			Name:            name,
			Addresses:       addressMap[name],
			BytesSent:       s.BytesSent,
			BytesRecv:       s.BytesRecv,
			BytesSentHuman:  bytesToHuman(s.BytesSent),
			BytesRecvHuman:  bytesToHuman(s.BytesRecv),
			PacketsSent:     s.PacketsSent,
			PacketsRecv:     s.PacketsRecv,
			Errin:           s.Errin,
			Errout:          s.Errout,
			Dropin:          s.Dropin,
			Dropout:         s.Dropout,
			IntervalSeconds: r.IntervalSeconds,
			TxBytesPerSec:   r.TxBytesPerSec,
			RxBytesPerSec:   r.RxBytesPerSec,
			TxHuman:         r.TxHuman,
			RxHuman:         r.RxHuman,
		})
	}
	return result
}

func readInterfaceAddressMap() map[string][]NetInterfaceAddress {
	out := make(map[string][]NetInterfaceAddress)
	interfaces, err := net.Interfaces()
	if err != nil {
		return out
	}

	for _, iface := range interfaces {
		if isIgnoredNIC(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		items := make([]NetInterfaceAddress, 0, len(addrs))
		for _, addr := range addrs {
			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil || ip == nil || ipNet == nil {
				continue
			}
			if ip.IsLoopback() {
				continue
			}
			family := "ipv4"
			if ip.To4() == nil {
				family = "ipv6"
			}
			prefix, _ := ipNet.Mask.Size()
			items = append(items, NetInterfaceAddress{
				Family:  family,
				Address: ip.String(),
				Prefix:  prefix,
			})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Family != items[j].Family {
				return items[i].Family < items[j].Family
			}
			if items[i].Address != items[j].Address {
				return items[i].Address < items[j].Address
			}
			return items[i].Prefix < items[j].Prefix
		})
		out[iface.Name] = items
	}
	return out
}

func NewCPUMonitor(interval time.Duration) *CPUMonitor {
	if interval <= 0 {
		interval = time.Second
	}
	model := ""
	if info, err := cpu.Info(); err == nil && len(info) > 0 {
		model = info[0].ModelName
	}
	return &CPUMonitor{
		interval: interval,
		model:    model,
	}
}

func (m *CPUMonitor) Start() {
	go func() {
		for {
			percent, err := cpu.Percent(m.interval, false)
			if err == nil && len(percent) > 0 {
				m.mu.Lock()
				m.usage = percent[0]
				m.ready = true
				m.mu.Unlock()
			}
		}
	}()
}

func (m *CPUMonitor) Get() (float64, string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.usage, m.model, m.ready
}
