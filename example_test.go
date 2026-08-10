package ip_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/skarm/ip"
)

func ExampleNew() {
	extractor := ip.Must(ip.New(
		ip.WithTrustedProxies("10.0.0.0/8"),
	))

	addr, err := extractor.ExtractFrom(map[string][]string{
		ip.XForwardedFor: {"198.51.100.7, 10.0.0.1"},
	}, "10.0.0.2:443")
	if err != nil {
		panic(err)
	}

	fmt.Println(addr)
	// Output:
	// 198.51.100.7
}

func ExampleExtractor_ExtractResultFrom() {
	extractor := ip.Must(ip.New(
		ip.WithTrustedProxies("10.0.0.0/8"),
	))

	result, err := extractor.ExtractResultFrom(map[string][]string{
		ip.XForwardedFor: {"198.51.100.7, 10.0.0.1"},
	}, "10.0.0.2:443")
	if err != nil {
		panic(err)
	}

	fmt.Println(result.Addr)
	fmt.Println(result.Header)
	fmt.Println(result.TrustedHops)
	fmt.Println(result.Source == ip.SourceProxyHeader)
	fmt.Println(result.Reason == ip.ReasonSelectedHeader)
	// Output:
	// 198.51.100.7
	// x-forwarded-for
	// 2
	// true
	// true
}

func ExampleExtractor_MiddlewareWithErrorHandler() {
	extractor := ip.Must(ip.New(
		ip.WithStrict(),
		ip.WithTrustedProxies("10.0.0.0/8"),
	))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := ip.Ctx(r.Context())
		fmt.Fprintln(w, addr)
	})

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://service.example", nil)
	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set(ip.XForwardedFor, "not-an-ip")

	response := httptest.NewRecorder()
	extractor.MiddlewareWithErrorHandler(
		next,
		func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		},
	).ServeHTTP(response, request)

	fmt.Println(response.Code)
	// Output:
	// 400
}
