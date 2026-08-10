package ip

import "net/http"

// HTTPErrorHandler handles an extraction error before a request reaches the
// wrapped handler. The function must write the complete HTTP response.
type HTTPErrorHandler func(http.ResponseWriter, *http.Request, error)

// Middleware returns best-effort HTTP middleware that stores a successfully
// extracted client IP in the request context.
//
// If extraction fails, Middleware discards the error and calls next with the
// original request context.
func (e *Extractor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if addr, err := e.Extract(r); err == nil {
			r = r.WithContext(WithContext(r.Context(), addr))
		}

		next.ServeHTTP(w, r)
	})
}

// MiddlewareWithErrorHandler returns HTTP middleware that stores a successfully
// extracted client IP in the request context. If extraction fails, it calls
// onError and does not call next.
//
// MiddlewareWithErrorHandler panics if onError is nil.
func (e *Extractor) MiddlewareWithErrorHandler(next http.Handler, onError HTTPErrorHandler) http.Handler {
	if onError == nil {
		panic("ip: nil HTTP error handler")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, err := e.Extract(r)
		if err != nil {
			onError(w, r, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), addr)))
	})
}
