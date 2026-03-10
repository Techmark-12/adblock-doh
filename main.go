package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Default blocklists if none specified in environment
var defaultBlocklists = []string{
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	"https://adaway.org/hosts.txt",
	"https://v.firebog.net/hosts/Easylist.txt",
}

type Config struct {
	Port        string   `json:"port"`
	UpstreamDNS []string `json:"upstream_dns"`
	Blocklists  []string `json:"blocklists"`
	Whitelist   []string `json:"whitelist"`
	CacheSize   int      `json:"cache_size"`
}

type Server struct {
	config    Config
	blocklist map[string]bool
	whitelist map[string]bool
	cache     *Cache
	upstream  []string
	mu        sync.RWMutex
	stats     Stats
	startTime time.Time
}

type Stats struct {
	TotalQueries   int64 `json:"total_queries"`
	BlockedQueries int64 `json:"blocked_queries"`
	CachedQueries  int64 `json:"cached_queries"`
}

type Cache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
	size  int
}

type cacheEntry struct {
	data     []byte
	expireAt time.Time
}

func NewCache(size int) *Cache {
	return &Cache{
		items: make(map[string]cacheEntry),
		size:  size,
	}
}

func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, found := c.items[key]
	if !found || time.Now().After(item.expireAt) {
		return nil, false
	}
	return item.data, true
}

func (c *Cache) Set(key string, data []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.size {
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.expireAt) {
				delete(c.items, k)
			}
		}
	}
	c.items[key] = cacheEntry{data: data, expireAt: time.Now().Add(ttl)}
}

func NewServer(config Config) *Server {
	whitelist := make(map[string]bool)
	for _, w := range config.Whitelist {
		whitelist[strings.ToLower(w)] = true
	}

	return &Server{
		config:    config,
		blocklist: make(map[string]bool),
		whitelist: whitelist,
		cache:     NewCache(config.CacheSize),
		upstream:  config.UpstreamDNS,
		startTime: time.Now(),
	}
}

func (s *Server) loadBlocklists() error {
	log.Println("Fetching blocklists...")
	newBlocklist := make(map[string]bool)

	for _, url := range s.config.Blocklists {
		log.Printf("Loading: %s", url)
		if err := s.fetchBlocklist(url, newBlocklist); err != nil {
			log.Printf("Failed to load %s: %v", url, err)
			continue
		}
	}

	s.mu.Lock()
	s.blocklist = newBlocklist
	s.mu.Unlock()

	log.Printf("Loaded %d blocked domains", len(newBlocklist))
	return nil
}

func (s *Server) fetchBlocklist(url string, blocklist map[string]bool) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	lineCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineCount++

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Handle different blocklist formats

		// Format 1: Hosts file (0.0.0.0 domain.com or 127.0.0.1 domain.com)
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			domain := strings.ToLower(fields[1])

			// Only block if IP is 0.0.0.0, 127.0.0.1, or ::1 (localhost)
			if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" {
				if domain != "localhost" && !strings.Contains(domain, "localhost") {
					blocklist[domain] = true
				}
			}
		} else if len(fields) == 1 {
			// Format 2: Plain domain list (one domain per line)
			domain := strings.ToLower(fields[0])

			// Skip if it looks like an IP address or contains invalid chars
			if !strings.Contains(domain, ".") || strings.Contains(domain, "/") {
				continue
			}

			// Remove trailing dot if present
			domain = strings.TrimSuffix(domain, ".")
			blocklist[domain] = true
		}

		// Format 3: AdGuard/ABP filter syntax (||domain^)
		if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			domain := strings.ToLower(line[2 : len(line)-1])
			domain = strings.TrimPrefix(domain, "www.")
			blocklist[domain] = true
		}

		// Format 4: Domain with path (block just the domain part)
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			// Extract domain from URL
			urlParts := strings.SplitN(line, "/", 3)
			if len(urlParts) >= 2 {
				domain := strings.ToLower(strings.Replace(urlParts[2], "www.", "", 1))
				blocklist[domain] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	log.Printf("Processed %d lines from %s", lineCount, url)
	return nil
}

func (s *Server) isBlocked(domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	if s.whitelist[domain] {
		return false
	}
	if s.blocklist[domain] {
		return true
	}

	// Check subdomains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if s.blocklist[parent] {
			return true
		}
	}
	return false
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	s.stats.TotalQueries++

	var body []byte
	var err error

	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		body, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Invalid base64", http.StatusBadRequest)
			return
		}
	} else if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	if len(msg.Question) == 0 {
		http.Error(w, "No question", http.StatusBadRequest)
		return
	}

	question := msg.Question[0]
	domain := question.Name

	cacheKey := fmt.Sprintf("%s:%d", domain, question.Qtype)
	if cached, found := s.cache.Get(cacheKey); found {
		s.stats.CachedQueries++
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(cached)
		return
	}

	if s.isBlocked(domain) {
		s.stats.BlockedQueries++
		msg.Rcode = dns.RcodeNameError
		msg.Response = true

		packed, _ := msg.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
		log.Printf("[BLOCKED] %s", domain)
		return
	}

	response, err := s.forwardQuery(msg)
	if err != nil {
		log.Printf("Forward error: %v", err)
		msg.Rcode = dns.RcodeServerFailure
		msg.Response = true
		packed, _ := msg.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
		return
	}

	packed, _ := response.Pack()
	ttl := 300 * time.Second
	if len(response.Answer) > 0 {
		if a, ok := response.Answer[0].(*dns.A); ok {
			ttl = time.Duration(a.Hdr.Ttl) * time.Second
		}
	}
	s.cache.Set(cacheKey, packed, ttl)

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func (s *Server) forwardQuery(r *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Timeout: 5 * time.Second}

	for _, server := range s.upstream {
		m, _, err := c.Exchange(r, server)
		if err == nil {
			return m, nil
		}
	}
	return nil, fmt.Errorf("all upstream failed")
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Build blocklist info
	blocklistHTML := ""
	for i, url := range s.config.Blocklists {
		blocklistHTML += fmt.Sprintf(`<li><code>%s</code></li>`, url)
		if i >= 4 { // Show max 5
			blocklistHTML += fmt.Sprintf(`<li>... and %d more</li>`, len(s.config.Blocklists)-5)
			break
		}
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Render DoH AdBlocker</title>
    <meta charset="utf-8">
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
        h1 { color: #38bdf8; margin-bottom: 10px; }
        .subtitle { color: #94a3b8; margin-bottom: 30px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-box { background: #1e293b; padding: 20px; border-radius: 8px; border-left: 4px solid #38bdf8; }
        .stat-value { font-size: 2em; font-weight: bold; color: #38bdf8; margin-top: 5px; }
        .blocked { border-left-color: #ef4444; }
        .blocked .stat-value { color: #ef4444; }
        .config { background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .blocklists { background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0; }
        code { background: #334155; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; word-break: break-all; }
        .url { word-break: break-all; color: #38bdf8; font-weight: 600; }
        button { background: #38bdf8; color: #0f172a; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 1em; margin-top: 10px; }
        button:hover { background: #7dd3fc; transform: translateY(-1px); }
        ul { line-height: 2; }
        li { margin-bottom: 8px; }
        .badge { display: inline-block; background: #10b981; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; margin-left: 10px; }
        .info-box { background: #334155; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid #f59e0b; }
    </style>
</head>
<body>
    <h1>🛡️ Render DoH AdBlocker <span class="badge">LIVE</span></h1>
    <p class="subtitle">DNS-over-HTTPS ad blocker with customizable blocklists</p>
    
    <div class="stats">
        <div class="stat-box">
            <div>Total Queries</div>
            <div class="stat-value" id="total">0</div>
        </div>
        <div class="stat-box blocked">
            <div>Blocked</div>
            <div class="stat-value" id="blocked">0</div>
        </div>
        <div class="stat-box">
            <div>Cached</div>
            <div class="stat-value" id="cached">0</div>
        </div>
        <div class="stat-box">
            <div>Blocklist Size</div>
            <div class="stat-value" id="blocklistSize">0</div>
        </div>
    </div>

    <div class="config">
        <h3>🔗 Setup Instructions</h3>
        <p><strong>DoH Endpoint:</strong><br><span class="url">https://` + r.Host + `/dns-query</span></p>
        
        <p><strong>Configure your devices:</strong></p>
        <ul>
            <li><strong>Android 9+:</strong> Settings → Network → Private DNS → <code>` + r.Host + `</code></li>
            <li><strong>iOS:</strong> Install <em>DNSCloak</em> → Add custom DoH → <code>https://` + r.Host + `/dns-query</code></li>
            <li><strong>Firefox:</strong> Settings → Privacy → DNS over HTTPS → <code>https://` + r.Host + `/dns-query</code></li>
            <li><strong>Chrome:</strong> Settings → Security → Secure DNS → <code>https://` + r.Host + `/dns-query</code></li>
        </ul>
    </div>

    <div class="blocklists">
        <h3>📋 Active Blocklists (` + fmt.Sprintf("%d", len(s.config.Blocklists)) + `)</h3>
        <ul>` + blocklistHTML + `</ul>
        <div class="info-box">
            <strong>💡 Tip:</strong> Add BLOCKLIST_URLS environment variable in Render dashboard to customize. 
            Use comma-separated URLs.<br>
            <code>BLOCKLIST_URLS=https://example.com/list1.txt,https://example.com/list2.txt</code>
        </div>
    </div>

    <button onclick="refresh()">🔄 Refresh Stats</button>

    <script>
        async function refresh() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('total').textContent = data.total_queries.toLocaleString();
                document.getElementById('blocked').textContent = data.blocked_queries.toLocaleString();
                document.getElementById('cached').textContent = data.cached_queries.toLocaleString();
                document.getElementById('blocklistSize').textContent = data.blocklist_size.toLocaleString();
            } catch (e) {
                console.error('Failed to fetch stats:', e);
            }
        }
        refresh();
        setInterval(refresh, 5000);
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	stats := map[string]interface{}{
		"total_queries":   s.stats.TotalQueries,
		"blocked_queries": s.stats.BlockedQueries,
		"cached_queries":  s.stats.CachedQueries,
		"uptime":          time.Since(s.startTime).Round(time.Second).String(),
		"blocklist_size":  len(s.blocklist),
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("Manual blocklist reload requested")
	if err := s.loadBlocklists(); err != nil {
		http.Error(w, fmt.Sprintf("Reload failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded", "domains": fmt.Sprintf("%d", len(s.blocklist))})
}

func (s *Server) startRefreshLoop() {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			log.Println("Auto-refreshing blocklists...")
			s.loadBlocklists()
		}
	}()
}

// parseBlocklistURLs parses comma-separated URLs from environment variable
func parseBlocklistURLs() []string {
	urlsEnv := os.Getenv("BLOCKLIST_URLS")
	if urlsEnv == "" {
		return defaultBlocklists
	}

	// Split by comma and trim spaces
	urls := strings.Split(urlsEnv, ",")
	var result []string
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" {
			result = append(result, url)
		}
	}

	if len(result) == 0 {
		return defaultBlocklists
	}

	log.Printf("Using %d custom blocklists from environment", len(result))
	return result
}

func loadConfig() Config {
	return Config{
		Port:        getEnv("PORT", "10000"),
		UpstreamDNS: []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"},
		Blocklists:  parseBlocklistURLs(),
		Whitelist:   []string{},
		CacheSize:   5000,
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	config := loadConfig()
	server := NewServer(config)

	// Log configuration
	log.Printf("Starting with %d blocklists:", len(config.Blocklists))
	for _, url := range config.Blocklists {
		log.Printf("  - %s", url)
	}

	if err := server.loadBlocklists(); err != nil {
		log.Printf("Warning: %v", err)
	}
	server.startRefreshLoop()

	http.HandleFunc("/", server.handleDashboard)
	http.HandleFunc("/api/stats", server.handleStats)
	http.HandleFunc("/api/reload", server.handleReload)
	http.HandleFunc("/dns-query", server.handleDoH)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	port := config.Port
	log.Printf("Server starting on port %s", port)

	if err := http.ListenAndServe("0.0.0.0:"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
