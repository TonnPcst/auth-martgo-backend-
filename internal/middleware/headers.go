package middleware

import "net/http"

// SecureHeaders adds security headers to every response.
//
// ENG: Sets nosniff, X-Frame-Options DENY, no-referrer and HSTS (2 years, including
// subdomains).
// LAO: ເພີ່ມ header ດ້ານຄວາມປອດໄພໃຫ້ທຸກ response.
//
// @param next - the next handler
// @returns the wrapped handler
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// APIHeaders adds headers for JSON API responses.
//
// ENG: Disables caching (Cache-Control: no-store) and sets a strict CSP, since the API
// never serves HTML.
// LAO: ເພີ່ມ header ສຳລັບ API — ຫ້າມ cache ແລະ ຕັ້ງ CSP ແບບເຂັ້ມງວດ.
//
// @param next - the next handler
// @returns the wrapped handler
func APIHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// CORS allows browser requests from a fixed list of origins.
//
// ENG: Echoes the Origin header back only when it is in the allow list. Answers
// preflight OPTIONS requests directly with 204 (cached for 10 minutes). Always adds
// "Vary: Origin" so caches keep responses per origin.
// LAO: ອະນຸຍາດ request ຈາກ browser ສະເພາະ origin ທີ່ຢູ່ໃນລາຍຊື່ — ຕອບ preflight ດ້ວຍ 204.
//
// @param allowedOrigins - exact origins allowed, e.g. "https://admin.example.com"
// @returns the middleware
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Add("Vary", "Origin")
			origin := r.Header.Get("Origin")
			if origin == "" || !allowed[origin] {
				next.ServeHTTP(w, r)
				return
			}

			h.Set("Access-Control-Allow-Origin", origin)
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.Set("Access-Control-Expose-Headers", "Retry-After")
			next.ServeHTTP(w, r)
		})
	}
}
