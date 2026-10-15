package middleware

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/TonnPcst/martgo-auth/internal/httpx"
)

type window struct {
	count   int
	resetAt time.Time
}

// RateLimit limits each client IP to a number of requests per time window.
//
// ENG: Uses a fixed window kept in memory, so the count is per instance and resets
// on restart. Expired windows are swept at most once per window. When over the limit
// it returns 429 with a Retry-After header.
// LAO: ຈຳກັດຈຳນວນ request ຕໍ່ IP ໃນຊ່ວງເວລາທີ່ກຳນົດ — ເກີນຈະຕອບ 429.
//
// @param limit - max requests allowed per window
// @param every - window length
// @returns the middleware
func RateLimit(limit int, every time.Duration) func(http.Handler) http.Handler {
	var (
		mu        sync.Mutex
		clients   = make(map[string]*window)
		lastSweep time.Time
	)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := clientIP(r)
			now := time.Now()

			mu.Lock()
			if now.Sub(lastSweep) > every {
				for k, win := range clients {
					if now.After(win.resetAt) {
						delete(clients, k)
					}
				}
				lastSweep = now
			}
			win, ok := clients[key]
			if !ok || now.After(win.resetAt) {
				win = &window{resetAt: now.Add(every)}
				clients[key] = win
			}
			win.count++
			count, resetAt := win.count, win.resetAt
			mu.Unlock()

			if count > limit {
				w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(resetAt).Seconds())+1))
				httpx.Error(w, http.StatusTooManyRequests, "too many requests, please try again later")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP returns the client IP from r.RemoteAddr without the port.
//
// ENG: When TRUST_PROXY is on, chi's RealIP middleware has already replaced RemoteAddr
// with the forwarded IP.
// LAO: ດຶງ IP ຂອງ client ຈາກ RemoteAddr (ຕັດ port ອອກ).
//
// @param r - incoming request
// @returns the IP, or the raw RemoteAddr if it cannot be split
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
