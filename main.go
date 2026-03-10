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

var defaultBlocklists = []string{
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	"https://adaway.org/hosts.txt",
	"https://v.firebog.net/hosts/Easylist.txt",
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Domain    string `json:"domain"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	ClientIP  string `json:"client_ip"`
	Reason    string `json:"reason,omitempty"`
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
	logs      []LogEntry
	logsMu    sync.RWMutex
	maxLogs   int
	clients   map[chan LogEntry]bool
	clientsMu sync.RWMutex
}

type Stats struct {
	TotalQueries   int64 `json:"total_queries"`
	BlockedQueries int64 `json:"blocked_queries"`
	CachedQueries  int64 `json:"cached_queries"`
}

type Cache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
	size  int
}

type cacheItem struct {
	data     []byte
	expireAt time.Time
}

func NewCache(size int) *Cache {
	return &Cache{
		items: make(map[string]cacheItem),
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
	c.items[key] = cacheItem{data: data, expireAt: time.Now().Add(ttl)}
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
		logs:      make([]LogEntry, 0),
		maxLogs:   1000,
		clients:   make(map[chan LogEntry]bool),
	}
}

func (s *Server) addLog(entry LogEntry) {
	s.logsMu.Lock()
	s.logs = append(s.logs, entry)
	if len(s.logs) > s.maxLogs {
		s.logs = s.logs[1:]
	}
	s.logsMu.Unlock()

	s.clientsMu.RLock()
	for client := range s.clients {
		select {
		case client <- entry:
		default:
		}
	}
	s.clientsMu.RUnlock()
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

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			domain := strings.ToLower(fields[1])

			if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" {
				if domain != "localhost" && !strings.Contains(domain, "localhost") {
					blocklist[domain] = true
				}
			}
		} else if len(fields) == 1 {
			domain := strings.ToLower(fields[0])
			if !strings.Contains(domain, ".") || strings.Contains(domain, "/") {
				continue
			}
			domain = strings.TrimSuffix(domain, ".")
			blocklist[domain] = true
		}

		if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			domain := strings.ToLower(line[2 : len(line)-1])
			domain = strings.TrimPrefix(domain, "www.")
			blocklist[domain] = true
		}

		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
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

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if s.blocklist[parent] {
			return true
		}
	}
	return false
}

func (s *Server) processDNSQuery(msg *dns.Msg, clientIP string) (*dns.Msg, bool, string) {
	if len(msg.Question) == 0 {
		return msg, false, "no question"
	}

	question := msg.Question[0]
	domain := question.Name
	qtype := dns.TypeToString[question.Qtype]
	if qtype == "" {
		qtype = fmt.Sprintf("TYPE%d", question.Qtype)
	}

	s.stats.TotalQueries++

	cacheKey := fmt.Sprintf("%s:%d", domain, question.Qtype)
	if cached, found := s.cache.Get(cacheKey); found {
		s.stats.CachedQueries++
		cachedMsg := new(dns.Msg)
		cachedMsg.Unpack(cached)
		cachedMsg.Id = msg.Id

		s.addLog(LogEntry{
			Timestamp: time.Now().Format("15:04:05"),
			Domain:    strings.TrimSuffix(domain, "."),
			Type:      qtype,
			Action:    "cached",
			ClientIP:  clientIP,
		})

		return cachedMsg, true, "cache hit"
	}

	if s.isBlocked(domain) {
		s.stats.BlockedQueries++
		msg.Rcode = dns.RcodeNameError
		msg.Response = true
		msg.RecursionAvailable = true

		s.addLog(LogEntry{
			Timestamp: time.Now().Format("15:04:05"),
			Domain:    strings.TrimSuffix(domain, "."),
			Type:      qtype,
			Action:    "blocked",
			ClientIP:  clientIP,
			Reason:    "blocklist",
		})

		return msg, true, "blocked"
	}

	return nil, false, "forward"
}

func (s *Server) forwardAndCache(msg *dns.Msg, cacheKey string, clientIP string) *dns.Msg {
	response, err := s.forwardQuery(msg)

	qtype := "A"
	if len(msg.Question) > 0 {
		qtype = dns.TypeToString[msg.Question[0].Qtype]
	}
	domain := ""
	if len(msg.Question) > 0 {
		domain = strings.TrimSuffix(msg.Question[0].Name, ".")
	}

	if err != nil {
		log.Printf("Forward error: %v", err)
		msg.Rcode = dns.RcodeServerFailure
		msg.Response = true
		msg.RecursionAvailable = true

		s.addLog(LogEntry{
			Timestamp: time.Now().Format("15:04:05"),
			Domain:    domain,
			Type:      qtype,
			Action:    "error",
			ClientIP:  clientIP,
			Reason:    err.Error(),
		})

		return msg
	}

	packed, _ := response.Pack()
	ttl := 300 * time.Second
	if len(response.Answer) > 0 {
		if a, ok := response.Answer[0].(*dns.A); ok {
			ttl = time.Duration(a.Hdr.Ttl) * time.Second
		}
	}
	s.cache.Set(cacheKey, packed, ttl)

	s.addLog(LogEntry{
		Timestamp: time.Now().Format("15:04:05"),
		Domain:    domain,
		Type:      qtype,
		Action:    "forwarded",
		ClientIP:  clientIP,
	})

	return response
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

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

	result, fromCache, action := s.processDNSQuery(msg, clientIP)
	if fromCache {
		packed, _ := result.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
		return
	}

	if action == "blocked" {
		packed, _ := result.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
		return
	}

	cacheKey := fmt.Sprintf("%s:%d", msg.Question[0].Name, msg.Question[0].Qtype)
	response := s.forwardAndCache(msg, cacheKey, clientIP)

	packed, _ := response.Pack()
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func (s *Server) handleSimpleDNS(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("name")
	if domain == "" {
		http.Error(w, "Missing name parameter", http.StatusBadRequest)
		return
	}

	qtype := dns.TypeA
	typeStr := r.URL.Query().Get("type")
	if typeStr != "" {
		switch strings.ToUpper(typeStr) {
		case "AAAA":
			qtype = dns.TypeAAAA
		case "CNAME":
			qtype = dns.TypeCNAME
		case "MX":
			qtype = dns.TypeMX
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)

	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	result, _, action := s.processDNSQuery(msg, clientIP)

	if action == "blocked" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"domain":  domain,
			"type":    typeStr,
			"blocked": true,
		})
		_ = result // Use result to avoid unused variable error
		return
	}

	cacheKey := fmt.Sprintf("%s:%d", dns.Fqdn(domain), qtype)
	response := s.forwardAndCache(msg, cacheKey, clientIP)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":   domain,
		"type":     typeStr,
		"blocked":  false,
		"response": response.Answer,
	})
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
	blocklistHTML := ""
	for i, url := range s.config.Blocklists {
		blocklistHTML += fmt.Sprintf("<li><code>%s</code></li>", url)
		if i >= 4 {
			remaining := len(s.config.Blocklists) - 5
			if remaining > 0 {
				blocklistHTML += fmt.Sprintf("<li>... and %d more</li>", remaining)
			}
			break
		}
	}

	host := r.Host

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Render DoH AdBlocker - Live Logs</title>
    <meta charset="utf-8">
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: system-ui, -apple-system, sans-serif; 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 20px; 
            background: #0f172a; 
            color: #e2e8f0; 
            line-height: 1.6; 
        }
        h1 { color: #38bdf8; margin-bottom: 10px; }
        .subtitle { color: #94a3b8; margin-bottom: 30px; }
        
        .grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 20px; 
            margin-bottom: 20px;
        }
        @media (max-width: 900px) {
            .grid { grid-template-columns: 1fr; }
        }
        
        .stats { 
            display: grid; 
            grid-template-columns: repeat(2, 1fr); 
            gap: 15px; 
        }
        .stat-box { 
            background: #1e293b; 
            padding: 20px; 
            border-radius: 8px; 
            border-left: 4px solid #38bdf8; 
        }
        .blocked { border-left-color: #ef4444; }
        .blocked .stat-value { color: #ef4444; }
        .cached { border-left-color: #10b981; }
        .cached .stat-value { color: #10b981; }
        .stat-value { 
            font-size: 2em; 
            font-weight: bold; 
            color: #38bdf8; 
            margin-top: 5px; 
        }
        
        .logs-container { 
            background: #1e293b; 
            border-radius: 8px; 
            padding: 20px;
            max-height: 500px;
            overflow: hidden;
        }
        .logs-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid #334155;
        }
        .logs-title { font-size: 1.2em; font-weight: bold; color: #38bdf8; }
        .logs-controls { display: flex; gap: 10px; }
        .btn {
            background: #334155;
            color: #e2e8f0;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
        }
        .btn:hover { background: #475569; }
        .btn.active { background: #38bdf8; color: #0f172a; }
        
        #logs {
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }
        .log-entry {
            display: grid;
            grid-template-columns: 70px 80px 200px 1fr 100px;
            gap: 10px;
            padding: 6px 10px;
            border-bottom: 1px solid #334155;
            animation: fadeIn 0.3s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateX(-10px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .log-entry:hover { background: #334155; }
        .log-time { color: #94a3b8; }
        .log-type { color: #38bdf8; font-weight: bold; }
        .log-domain { color: #e2e8f0; overflow: hidden; text-overflow: ellipsis; }
        .log-action { 
            padding: 2px 8px; 
            border-radius: 4px; 
            font-size: 0.85em;
            font-weight: bold;
            text-align: center;
        }
        .action-blocked { background: #ef4444; color: white; }
        .action-cached { background: #10b981; color: white; }
        .action-forwarded { background: #38bdf8; color: #0f172a; }
        .action-error { background: #f59e0b; color: #0f172a; }
        .log-client { color: #64748b; font-size: 0.8em; }
        
        .config { background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .blocklists { background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0; }
        code { background: #334155; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; word-break: break-all; }
        .url { word-break: break-all; color: #38bdf8; font-weight: 600; }
        button { background: #38bdf8; color: #0f172a; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 1em; }
        button:hover { background: #7dd3fc; }
        ul { line-height: 2; }
        .badge { display: inline-block; background: #10b981; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; margin-left: 10px; }
        .status-indicator { display: inline-block; width: 8px; height: 8px; border-radius: 50%%; margin-right: 5px; }
        .status-live { background: #10b981; animation: pulse 2s infinite; }
        @keyframes pulse {
            0%%, 100%% { opacity: 1; }
            50%% { opacity: 0.5; }
        }
        .filter-group { display: flex; gap: 5px; }
    </style>
</head>
<body>
    <h1>🛡️ Render DoH AdBlocker <span class="badge">LIVE</span></h1>
    <p class="subtitle">Real-time DNS logging and ad blocking</p>
    
    <div class="grid">
        <div>
            <div class="stats">
                <div class="stat-box">
                    <div>Total Queries</div>
                    <div class="stat-value" id="total">0</div>
                </div>
                <div class="stat-box blocked">
                    <div>Blocked</div>
                    <div class="stat-value" id="blocked">0</div>
                </div>
                <div class="stat-box cached">
                    <div>Cached</div>
                    <div class="stat-value" id="cached">0</div>
                </div>
                <div class="stat-box">
                    <div>Blocklist Size</div>
                    <div class="stat-value" id="blocklistSize">0</div>
                </div>
            </div>
            
            <div class="config" style="margin-top: 20px;">
                <h3>🔗 Connection Info</h3>
                <p><strong>DoH Endpoint:</strong><br><span class="url">https://%s/dns-query</span></p>
                <p><strong>Simple API:</strong><br><span class="url">https://%s/dns?name=example.com</span></p>
            </div>
        </div>
        
        <div class="logs-container">
            <div class="logs-header">
                <div class="logs-title">
                    <span class="status-indicator status-live"></span>
                    Live Logs
                </div>
                <div class="logs-controls">
                    <div class="filter-group">
                        <button class="btn active" onclick="filterLogs('all')" id="filter-all">All</button>
                        <button class="btn" onclick="filterLogs('blocked')" id="filter-blocked">Blocked</button>
                        <button class="btn" onclick="filterLogs('cached')" id="filter-cached">Cached</button>
                    </div>
                    <button class="btn" onclick="clearLogs()">Clear</button>
                    <button class="btn" onclick="pauseLogs()" id="pause-btn">Pause</button>
                </div>
            </div>
            <div id="logs"></div>
        </div>
    </div>

    <div class="blocklists">
        <h3>📋 Active Blocklists (%d)</h3>
        <ul>%s</ul>
    </div>

    <script>
        let eventSource;
        let isPaused = false;
        let currentFilter = 'all';
        let logCount = 0;
        
        function connectSSE() {
            eventSource = new EventSource('/api/logs/stream');
            
            eventSource.onmessage = (event) => {
                if (isPaused) return;
                
                const entry = JSON.parse(event.data);
                addLogEntry(entry);
            };
            
            eventSource.onerror = (err) => {
                console.log('SSE error, reconnecting...');
                setTimeout(connectSSE, 3000);
            };
        }
        
        function addLogEntry(entry) {
            const logsDiv = document.getElementById('logs');
            
            if (currentFilter !== 'all' && entry.action !== currentFilter) {
                return;
            }
            
            const div = document.createElement('div');
            div.className = 'log-entry';
            div.innerHTML = '<span class="log-time">' + entry.timestamp + '</span>' +
                '<span class="log-type">' + entry.type + '</span>' +
                '<span class="log-domain" title="' + entry.domain + '">' + entry.domain + '</span>' +
                '<span class="log-action action-' + entry.action + '">' + entry.action.toUpperCase() + '</span>' +
                '<span class="log-client">' + entry.client_ip.split(':')[0] + '</span>';
            
            logsDiv.insertBefore(div, logsDiv.firstChild);
            
            while (logsDiv.children.length > 100) {
                logsDiv.removeChild(logsDiv.lastChild);
            }
            
            logCount++;
        }
        
        function filterLogs(type) {
            currentFilter = type;
            document.querySelectorAll('.filter-group .btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.getElementById('filter-' + type).classList.add('active');
            document.getElementById('logs').innerHTML = '';
            logCount = 0;
        }
        
        function clearLogs() {
            document.getElementById('logs').innerHTML = '';
            logCount = 0;
        }
        
        function pauseLogs() {
            isPaused = !isPaused;
            document.getElementById('pause-btn').textContent = isPaused ? 'Resume' : 'Pause';
        }
        
        async function updateStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('total').textContent = data.total_queries.toLocaleString();
                document.getElementById('blocked').textContent = data.blocked_queries.toLocaleString();
                document.getElementById('cached').textContent = data.cached_queries.toLocaleString();
                document.getElementById('blocklistSize').textContent = data.blocklist_size.toLocaleString();
            } catch (e) {
                console.error('Stats error:', e);
            }
        }
        
        async function loadRecentLogs() {
            try {
                const res = await fetch('/api/logs');
                const logs = await res.json();
                logs.reverse().forEach(entry => addLogEntry(entry));
            } catch (e) {
                console.error('Failed to load recent logs:', e);
            }
        }
        
        loadRecentLogs();
        connectSSE();
        updateStats();
        setInterval(updateStats, 5000);
    </script>
</body>
</html>`, host, host, len(s.config.Blocklists), blocklistHTML)

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

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	s.logsMu.RLock()
	logs := make([]LogEntry, len(s.logs))
	copy(logs, s.logs)
	s.logsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	client := make(chan LogEntry, 100)

	s.clientsMu.Lock()
	s.clients[client] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, client)
		s.clientsMu.Unlock()
		close(client)
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case entry, ok := <-client:
			if !ok {
				return
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
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
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "reloaded",
		"domains": fmt.Sprintf("%d", len(s.blocklist)),
	})
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

func parseBlocklistURLs() []string {
	urlsEnv := os.Getenv("BLOCKLIST_URLS")
	if urlsEnv == "" {
		return defaultBlocklists
	}

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
	http.HandleFunc("/api/logs", server.handleLogs)
	http.HandleFunc("/api/logs/stream", server.handleLogsStream)
	http.HandleFunc("/api/reload", server.handleReload)
	http.HandleFunc("/dns-query", server.handleDoH)
	http.HandleFunc("/dns", server.handleSimpleDNS)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	port := config.Port
	log.Printf("Server starting on port %s", port)
	log.Printf("Dashboard: http://localhost:%s", port)

	if err := http.ListenAndServe("0.0.0.0:"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
