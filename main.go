// Throwaway probe for Fount Cloud's runner link (fount-broker internal/link):
// can two Tinfoil enclaves run it through their shims? Two instances of one
// release each pin the release's repository, then one dials the other on
// /fount-link and runs the checks below. It holds no secret: the only key is
// the enclave's per-boot fount-link key, and only echoes cross the link.
//
//	GET  /self                 this enclave's own document checked against PEER_PIN
//	POST /run?peer=https://<domain>[&hold=35]
//	GET  /status               what /run found, and the links this end served
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/zeke-02/link-probe/link"
)

var listenAddr = ":8080"

func main() {
	if a := os.Getenv("LISTEN_ADDR"); a != "" {
		listenAddr = a
	}
	if len(os.Args) > 1 && os.Args[1] == "health" {
		// The image is FROM scratch, so the binary is its own healthcheck.
		resp, err := http.Get("http://127.0.0.1" + listenAddr + "/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	p := &probe{pin: os.Getenv("PEER_PIN"), wrongPin: os.Getenv("WRONG_PIN"), results: map[string]any{}}
	// A failure here is reported on /status rather than stopping the
	// container, so a failed deploy doesn't hide it.
	if os.Getenv("PROBE_UNATTESTED") == "1" {
		// Local runs of the probe itself, outside an enclave.
		p.side, p.sideErr = link.Unattested()
	} else {
		p.side, p.sideErr = link.Tinfoil(p.pin)
	}
	if p.sideErr != nil {
		log.Printf("the link side: %v", p.sideErr)
	} else {
		log.Printf("fount-link key %s, pinning %s", fingerprint(p.side.Key.Public().(ed25519.PublicKey)), p.pin)
	}

	tl, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	upgrades := link.NewListener(tl.Addr())
	go p.serveLinks(upgrades)
	mux := http.NewServeMux()
	mux.Handle(link.Path, upgrades)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /self", p.self)
	mux.HandleFunc("POST /run", p.run)
	mux.HandleFunc("GET /status", p.status)
	log.Fatal((&http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}).Serve(tl))
}

type probe struct {
	pin, wrongPin string
	side          *link.Side
	sideErr       error

	mu      sync.Mutex
	results map[string]any
	served  []map[string]any
	running bool
}

func fingerprint(k ed25519.PublicKey) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:8])
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	enc.Encode(v)
}

func (p *probe) put(key string, v any) {
	p.mu.Lock()
	p.results[key] = v
	p.mu.Unlock()
	b, _ := json.Marshal(v)
	log.Printf("%s: %s", key, b)
}

// serveLinks is the runner's end: each upgraded connection runs the
// handshake, then echoes until the dialler closes.
func (p *probe) serveLinks(l *link.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			start := time.Now()
			entry := map[string]any{"at": start.UTC().Format(time.RFC3339), "remote": conn.RemoteAddr().String()}
			defer func() {
				p.mu.Lock()
				p.served = append(p.served, entry)
				if len(p.served) > 50 {
					p.served = p.served[1:]
				}
				p.mu.Unlock()
			}()
			if p.side == nil {
				entry["error"] = "no link side: " + errString(p.sideErr)
				return
			}
			tc, err := p.side.Server(context.Background(), conn)
			entry["handshake_ms"] = time.Since(start).Milliseconds()
			if err != nil {
				entry["error"] = err.Error()
				entry["refused_peer"] = errors.Is(err, link.ErrPeer)
				return
			}
			defer tc.Close()
			n, err := io.Copy(tc, tc)
			entry["echoed_bytes"] = n
			entry["open_s"] = int(time.Since(start).Seconds())
			entry["ended"] = errString(err)
		}()
	}
}

// self checks this enclave's own document as a peer would: the socket
// answers, the fount-link key is endorsed and is the key Tinfoil granted.
func (p *probe) self(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, p.selfCheck(r.Context()))
}

func (p *probe) selfCheck(ctx context.Context) map[string]any {
	out := map[string]any{"pin": p.pin}
	if p.side == nil {
		out["error"] = "no link side: " + errString(p.sideErr)
		return out
	}
	mine := p.side.Key.Public().(ed25519.PublicKey)
	out["key"] = fingerprint(mine)
	nonce := make([]byte, 32)
	rand.Read(nonce)
	start := time.Now()
	doc, err := p.side.Attester.Attest(ctx, nonce)
	out["attest_ms"] = time.Since(start).Milliseconds()
	if err != nil {
		out["error"] = "attest: " + err.Error()
		return out
	}
	out["document_bytes"] = len(doc)
	start = time.Now()
	endorsed, err := p.side.Check(doc, nonce)
	out["verify_ms"] = time.Since(start).Milliseconds()
	if err != nil {
		out["error"] = "verify: " + err.Error()
		return out
	}
	out["endorsed_key"] = fingerprint(endorsed)
	out["endorses_own_key"] = endorsed.Equal(mine)
	// And a wrong nonce must fail: the check really binds the session.
	other := make([]byte, 32)
	rand.Read(other)
	_, err = p.side.Check(doc, other)
	out["other_nonce_refused"] = err != nil
	return out
}

func (p *probe) status(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"pin": p.pin, "running": p.running, "results": p.results, "served": p.served})
}

func (p *probe) run(w http.ResponseWriter, r *http.Request) {
	peer := r.URL.Query().Get("peer")
	hold := 35
	if h := r.URL.Query().Get("hold"); h != "" {
		n, err := strconv.Atoi(h)
		if err != nil || n < 0 || n > 120 {
			http.Error(w, "hold is minutes, 0 to 120", http.StatusBadRequest)
			return
		}
		hold = n
	}
	if peer == "" {
		http.Error(w, "peer=https://<domain>", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		http.Error(w, "a run is going", http.StatusConflict)
		return
	}
	p.running = true
	p.results = map[string]any{"peer": peer, "started": time.Now().UTC().Format(time.RFC3339), "hold_minutes": hold}
	p.mu.Unlock()
	go func() {
		p.checks(peer, time.Duration(hold)*time.Minute)
		p.mu.Lock()
		p.running = false
		p.results["finished"] = time.Now().UTC().Format(time.RFC3339)
		p.mu.Unlock()
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started; poll /status"})
}

func (p *probe) checks(peer string, hold time.Duration) {
	ctx := context.Background()
	p.put("self", p.selfCheck(ctx))
	if p.side == nil {
		return
	}

	// 1. The link, as the coordinator dials it.
	start := time.Now()
	tc, err := p.dial(ctx, peer, p.side)
	p.put("link", map[string]any{"ok": err == nil, "ms": time.Since(start).Milliseconds(), "error": errString(err)})
	if err != nil {
		return
	}
	defer tc.Close()

	// 2. The proxy's path to a coordinator's attested key: the peer's document
	// from its public shim, for a nonce of ours, must endorse the key the peer
	// just proved over the link.
	p.put("public_attestation", p.publicAttestation(ctx, peer, tc))

	// 3. Bulk both ways at once, as a job's workspace and results travel.
	p.put("echo_16MiB", echo(tc, 16<<20))

	// 4. A coordinator pinning another repository must refuse this peer.
	if p.wrongPin != "" {
		wrong := *p.side
		check, err := link.TinfoilChecker(p.wrongPin)
		if err != nil {
			p.put("wrong_pin", map[string]any{"error": "checker: " + err.Error()})
		} else {
			wrong.Check = check
			c, err := p.dial(ctx, peer, &wrong)
			if c != nil {
				c.Close()
			}
			p.put("wrong_pin", map[string]any{"pin": p.wrongPin, "refused": errors.Is(err, link.ErrPeer), "error": errString(err)})
		}
	}

	// 5. The peer must refuse a dialler with no attestation, even one that
	// accepts the peer's.
	if u, err := link.Unattested(); err == nil {
		u.Check = p.side.Check
		c, err := p.dial(ctx, peer, u)
		out := map[string]any{"our_handshake": errString(err)}
		if err == nil {
			c.SetDeadline(time.Now().Add(30 * time.Second))
			_, werr := c.Write([]byte("x"))
			_, rerr := c.Read(make([]byte, 1))
			out["peer_refused"] = werr != nil || rerr != nil
			out["after"] = errString(errors.Join(werr, rerr))
			c.Close()
		} else {
			out["peer_refused"] = true
		}
		p.put("unattested_dialler", out)
	}

	// 6. Idle, as a job thinks without output.
	time.Sleep(90 * time.Second)
	p.put("after_idle_90s", echo(tc, 1024))

	// 7. Held open past a job's 30-minute timeout, a small echo each minute.
	start = time.Now()
	var last map[string]any
	for time.Since(start) < hold {
		time.Sleep(time.Minute)
		last = echo(tc, 1024)
		last["open_minutes"] = int(time.Since(start).Minutes())
		p.put("hold", last)
		if last["ok"] != true {
			break
		}
	}
}

func (p *probe) publicAttestation(ctx context.Context, peer string, conn net.Conn) map[string]any {
	out := map[string]any{}
	tc, ok := conn.(*tls.Conn)
	if !ok || len(tc.ConnectionState().PeerCertificates) == 0 {
		out["error"] = "no peer certificate on the link"
		return out
	}
	linkKey, _ := tc.ConnectionState().PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, peer+"/.well-known/tinfoil-attestation?nonce="+hex.EncodeToString(nonce), nil)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	doc, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	resp.Body.Close()
	out["status"] = resp.StatusCode
	out["fetch_ms"] = time.Since(start).Milliseconds()
	out["document_bytes"] = len(doc)
	if resp.StatusCode != http.StatusOK {
		out["error"] = fmt.Sprintf("%.300s", doc)
		return out
	}
	endorsed, err := p.side.Check(doc, nonce)
	if err != nil {
		out["error"] = "verify: " + err.Error()
		return out
	}
	out["endorses_link_key"] = endorsed.Equal(linkKey)
	return out
}

// dial is the coordinator's side: the upgrade through the peer's shim, then
// the handshake.
func (p *probe) dial(ctx context.Context, peer string, side *link.Side) (net.Conn, error) {
	conn, err := link.Dial(ctx, peer)
	if err != nil {
		return nil, fmt.Errorf("upgrade: %w", err)
	}
	tc, err := side.Client(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

// echo sends n random bytes while reading them back, and checks they match.
func echo(c net.Conn, n int) map[string]any {
	c.SetDeadline(time.Now().Add(5 * time.Minute))
	defer c.SetDeadline(time.Time{})
	data := make([]byte, n)
	rand.Read(data)
	start := time.Now()
	sent := make(chan error, 1)
	go func() {
		_, err := c.Write(data)
		sent <- err
	}()
	got := make([]byte, n)
	_, rerr := io.ReadFull(c, got)
	werr := <-sent
	secs := time.Since(start).Seconds()
	out := map[string]any{"bytes": n, "s": round(secs), "ok": rerr == nil && werr == nil && bytes.Equal(data, got)}
	if secs > 0 {
		out["MiB_per_s"] = round(float64(n) / (1 << 20) / secs)
	}
	if err := errors.Join(werr, rerr); err != nil {
		out["error"] = err.Error()
	}
	return out
}

func round(f float64) float64 { return float64(int(f*1000)) / 1000 }
