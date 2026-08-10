package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	inputFile      = "proxy_gabungan_final.csv"
	outputDetail   = "proxy_health.txt"
	outputAlive    = "proxy_alive.txt"
	requestTimeout = 8 * time.Second
	workers        = 70
	retryCount     = 1
)

var checkEndpoints = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"http://checkip.amazonaws.com/",
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
}

type ProxyResult struct {
	Address   string
	Type      string
	Alive     bool
	Latency   time.Duration
	Anonymous bool
	Country   string
	Error     string
}

type ProxyEntry struct {
	Type  string
	IP    string
	Port  string
	GeoIP string
}

func main() {
	rand.Seed(time.Now().UnixNano())

	entries, err := loadProxiesFromCSV(inputFile)
	if err != nil {
		log.Fatalf("❌ Gagal load CSV: %v", err)
	}
	fmt.Printf("📦 Total proxy dimuat: %d\n", len(entries))

	jobs := make(chan ProxyEntry, len(entries))
	results := make(chan ProxyResult, len(entries))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, results)
	}

	for _, e := range entries {
		jobs <- e
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var aliveList, deadList []ProxyResult
	count := 0
	total := len(entries)

	for r := range results {
		count++
		if r.Alive {
			aliveList = append(aliveList, r)
			fmt.Printf("[%d/%d] ✅ %s (%s) | %v | %s\n", count, total, r.Address, r.Type, r.Latency.Round(time.Millisecond), r.Country)
		} else {
			deadList = append(deadList, r)
			fmt.Printf("[%d/%d] ❌ %s (%s) -> %s\n", count, total, r.Address, r.Type, r.Error)
		}
	}

	if err := saveResults(outputDetail, outputAlive, aliveList, deadList); err != nil {
		log.Fatalf("❌ Gagal simpan hasil: %v", err)
	}

	fmt.Println("\n──────── RINGKASAN ────────")
	fmt.Printf("Total : %d\n", total)
	fmt.Printf("Hidup : %d (%.1f%%)\n", len(aliveList), percent(len(aliveList), total))
	fmt.Printf("Mati  : %d (%.1f%%)\n", len(deadList), percent(len(deadList), total))
	fmt.Printf("📄 File Laporan   : %s\n", outputDetail)
	fmt.Printf("📄 File Proxy Live: %s\n", outputAlive)
}

// ─── Worker ───────────────────────────────────────────────────────────

func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan ProxyEntry, results chan<- ProxyResult) {
	defer wg.Done()

	baseTransport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      1,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	defer baseTransport.CloseIdleConnections()

	for entry := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		results <- checkProxy(ctx, baseTransport, entry)
	}
}

// ─── Native SOCKS4 ────────────────────────────────────────────────────

// makeSocks4Dialer membuat dialer untuk SOCKS4.
// Tidak perlu dependency eksternal.
func makeSocks4Dialer(proxyAddr string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Buat timeout dari context
		deadline, _ := ctx.Deadline()
		timeout := requestTimeout
		if !deadline.IsZero() {
			timeout = time.Until(deadline)
			if timeout <= 0 {
				return nil, fmt.Errorf("context deadline exceeded")
			}
		}

		// 1. Konek ke proxy SOCKS4
		conn, err := net.DialTimeout(network, proxyAddr, timeout)
		if err != nil {
			return nil, fmt.Errorf("konek ke socks4 proxy gagal: %w", err)
		}

		// 2. Parse target addr (host:port)
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("invalid target addr: %w", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("invalid port: %w", err)
		}

		// 3. Resolve IP target (SOCKS4 butuh IP 4 byte, tidak support hostname tanpa resolve)
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			conn.Close()
			return nil, fmt.Errorf("resolve target IP gagal: %w", err)
		}
		ip4 := ips[0].To4()
		if ip4 == nil {
			conn.Close()
			return nil, fmt.Errorf("target bukan IPv4: %s", host)
		}

		// 4. Kirim handshake SOCKS4
		// Format: [4, 1, port_high, port_low, ip0, ip1, ip2, ip3, 0x00]
		req := make([]byte, 9)
		req[0] = 0x04
		req[1] = 0x01 // CONNECT
		binary.BigEndian.PutUint16(req[2:4], uint16(port))
		copy(req[4:8], ip4)
		req[8] = 0x00 // User ID kosong

		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks4 write gagal: %w", err)
		}

		// 5. Baca response (8 byte)
		resp := make([]byte, 8)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks4 read response gagal: %w", err)
		}

		// Byte ke-1 harus 0x5A (90) artinya sukses
		if resp[1] != 0x5A {
			conn.Close()
			return nil, fmt.Errorf("socks4 rejected (code %d)", resp[1])
		}

		return conn, nil
	}
}

// ─── Pengecekan Proxy ────────────────────────────────────────────────

func checkProxy(ctx context.Context, baseTransport *http.Transport, entry ProxyEntry) ProxyResult {
	res := ProxyResult{
		Address: entry.IP + ":" + entry.Port,
		Type:    entry.Type,
		Country: entry.GeoIP,
	}

	transport := baseTransport.Clone()
	defer transport.CloseIdleConnections()

	proxyAddr := entry.IP + ":" + entry.Port

	switch strings.ToLower(entry.Type) {
	case "http", "https":
		proxyURL := fmt.Sprintf("http://%s", proxyAddr)
		u, err := url.Parse(proxyURL)
		if err != nil {
			res.Error = "invalid http proxy url"
			return res
		}
		transport.Proxy = http.ProxyURL(u)

	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{Timeout: requestTimeout})
		if err != nil {
			res.Error = "socks5 dialer error: " + err.Error()
			return res
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}

	case "socks4":
		// 🚀 NATIVE SOCKS4 — TANPA DEPENDENCY EKSTERNAL
		socks4Dialer := makeSocks4Dialer(proxyAddr)
		transport.DialContext = socks4Dialer

	default:
		res.Error = "unknown type " + entry.Type
		return res
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}
			return nil
		},
	}

	var lastErr error
	for attempt := 0; attempt <= retryCount; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		start := time.Now()

		for _, ep := range checkEndpoints {
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ep, nil)
			if err != nil {
				lastErr = err
				continue
			}
			req.Header.Set("User-Agent", randomUA())

			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				if strings.Contains(err.Error(), "EOF") {
					lastErr = fmt.Errorf("koneksi ditutup proxy (EOF)")
					break
				}
				continue
			}

			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				parsed, pErr := parseResponse(ep, string(bodyBytes))
				if pErr == nil {
					cancel()
					res.Alive = true
					res.Latency = time.Since(start)
					if parsed.Country != "" {
						res.Country = parsed.Country
					}
					res.Anonymous = parsed.Anonymous
					return res
				}
				lastErr = pErr
			} else {
				lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}
		cancel()
	}

	res.Error = errStr(lastErr)
	return res
}

// ─── Parse Response ──────────────────────────────────────────────────

type ParsedData struct {
	IP        string
	Country   string
	Anonymous bool
}

func parseResponse(urlStr, body string) (ParsedData, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return ParsedData{}, fmt.Errorf("empty response")
	}

	if strings.Contains(urlStr, "1.1.1.1") {
		lines := strings.Split(body, "\n")
		var ip, loc string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ip=") {
				ip = strings.TrimPrefix(line, "ip=")
			}
			if strings.HasPrefix(line, "loc=") {
				loc = strings.TrimPrefix(line, "loc=")
			}
		}
		if ip != "" {
			return ParsedData{IP: ip, Country: loc, Anonymous: true}, nil
		}
		return ParsedData{}, fmt.Errorf("cf trace parse fail")
	}

	if strings.Contains(urlStr, "checkip.amazonaws.com") {
		ip := strings.TrimSpace(body)
		if ip != "" {
			return ParsedData{IP: ip, Country: "Unknown", Anonymous: true}, nil
		}
		return ParsedData{}, fmt.Errorf("empty IP from aws")
	}

	return ParsedData{}, fmt.Errorf("unknown endpoint")
}

// ─── Helper ──────────────────────────────────────────────────────────

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func errStr(e error) string {
	if e == nil {
		return "unknown"
	}
	msg := e.Error()
	if len(msg) > 80 {
		msg = msg[:80] + "..."
	}
	return msg
}

func percent(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

// ─── Load CSV ──────────────────────────────────────────────────────

func loadProxiesFromCSV(path string) ([]ProxyEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("file CSV kosong")
	}

	var entries []ProxyEntry
	for i, row := range records {
		if i == 0 && len(row) >= 4 && (row[0] == "type" || row[0] == "Type") {
			continue
		}
		if len(row) < 4 {
			continue
		}
		entries = append(entries, ProxyEntry{
			Type:  strings.TrimSpace(row[0]),
			IP:    strings.TrimSpace(row[1]),
			Port:  strings.TrimSpace(row[2]),
			GeoIP: strings.TrimSpace(row[3]),
		})
	}
	return entries, nil
}

// ─── Save Results ──────────────────────────────────────────────────

func saveResults(detailPath, alivePath string, alive, dead []ProxyResult) error {
	sort.Slice(alive, func(i, j int) bool {
		return alive[i].Latency < alive[j].Latency
	})

	detailFile, err := os.Create(detailPath)
	if err != nil {
		return err
	}
	defer detailFile.Close()
	wDetail := bufio.NewWriter(detailFile)
	defer wDetail.Flush()

	fmt.Fprintln(wDetail, "================ PROXY HEALTH REPORT ================")
	fmt.Fprintf(wDetail, "Generated : %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(wDetail, "Alive     : %d\n", len(alive))
	fmt.Fprintln(wDetail, "=====================================================")
	fmt.Fprintln(wDetail)

	fmt.Fprintln(wDetail, "── ALIVE ──")
	for _, r := range alive {
		fmt.Fprintf(wDetail, "%s (%s) | %dms | %s\n", r.Address, r.Type, r.Latency.Milliseconds(), r.Country)
	}

	aliveFile, err := os.Create(alivePath)
	if err != nil {
		return err
	}
	defer aliveFile.Close()
	wAlive := bufio.NewWriter(aliveFile)
	defer wAlive.Flush()

	for _, r := range alive {
		fmt.Fprintf(wAlive, "%s, %s, %dms\n", r.Address, strings.ToUpper(r.Type), r.Latency.Milliseconds())
	}

	return nil
}
