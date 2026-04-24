package ip

import "net/http"

// Middleware stores the extracted client IP in the request context.
//
// If extraction fails, the middleware leaves the context unchanged.
func (e *Extractor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip, err := e.Extract(r); err == nil {
			r = r.WithContext(WithContext(r.Context(), ip))
		}

		next.ServeHTTP(w, r)
	})
}
