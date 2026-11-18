package pam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	coreconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSafeHTTPWireAndConvenienceMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" || r.Header.Get("X-Test") != "value" {
			t.Error("request headers were lost")
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"token":"synthetic"}` || r.Header.Get("Content-Type") != "application/json" {
				t.Error("JSON request changed")
			}
		} else if r.URL.Query().Get("id") != "a+ /中文" || len(r.URL.Query()["existing"]) != 2 {
			t.Error("query encoding or merging changed")
		}
		w.Header().Set("X-Request-ID", "request-id")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"active":true}`)
	}))
	defer server.Close()
	c := newSafeHTTPClient(coreconfig.DefaultHttpConfiguration())
	defer c.CloseIdleConnections()
	response, err := c.Post(server.URL, map[string]string{"X-Test": "value"}, map[string]string{"token": "synthetic"})
	if err != nil || response.StatusCode != 201 || response.RequestId() != "request-id" || string(response.Body) != `{"active":true}` {
		t.Fatalf("POST response changed: %v", err)
	}
	request := &domain.HttpRequest{Method: enums.HttpMethodGet, URL: server.URL + "?existing=one",
		Headers: map[string]string{"X-Test": "value"}, QueryParams: url.Values{"id": {"a+ /中文"}, "existing": {"two"}}}
	if _, err := c.ExecuteContext(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(server.URL+"?existing=one&existing=two&id="+url.QueryEscape("a+ /中文"), request.Headers); err != nil {
		t.Fatal(err)
	}
}

func TestSafeHTTPOptionsAndTLS(t *testing.T) {
	c := newSafeHTTPClient(&coreconfig.HttpConfiguration{ConnectTimeout: 1234, ReadTimeout: 5678})
	defer c.CloseIdleConnections()
	transport := c.client.Transport.(*http.Transport)
	if c.client.Timeout != 5678*time.Millisecond || transport.ResponseHeaderTimeout != c.client.Timeout ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default transport options changed")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	_, err := c.Get(server.URL, nil)
	assertTransportCode(t, err, constants.TlsHandshakeFailed, 0)
	insecure := newSafeHTTPClient(&coreconfig.HttpConfiguration{ReadTimeout: 1000, UnsafeIgnoreSSLCert: true})
	defer insecure.CloseIdleConnections()
	if _, err := insecure.Get(server.URL, nil); err != nil {
		t.Fatal("explicit test TLS option was not applied", err)
	}
}

func TestSafeHTTPFailuresAndResponseLimit(t *testing.T) {
	c := newSafeHTTPClient(coreconfig.DefaultHttpConfiguration())
	defer c.CloseIdleConnections()
	_, err := c.Get("http://bad:%", nil)
	assertTransportCode(t, err, constants.InvalidURL, 0)
	_, err = c.ExecuteContext(context.Background(), &domain.HttpRequest{URL: "http://example.test", Method: "bad method"})
	assertTransportCode(t, err, constants.ClientError, 0)
	_, err = c.Post("http://example.test", nil, make(chan int))
	var encoding *coreerrors.EncodingError
	if !errors.As(err, &encoding) {
		t.Fatal("invalid JSON input was not classified")
	}
	for _, size := range []int{maxPAMResponseBytes, maxPAMResponseBytes + 1} {
		c.client.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", size)))}, nil
		})
		response, err := c.Get("http://example.test", nil)
		if size == maxPAMResponseBytes {
			if err != nil || len(response.Body) != size {
				t.Fatal("response size boundary rejected")
			}
		} else {
			assertTransportCode(t, err, constants.ResponseTooLarge, 200)
			if response != nil {
				t.Fatal("oversized response returned partial data")
			}
		}
	}
	c.client.Transport = transportFunc(func(*http.Request) (*http.Response, error) { return nil, context.Canceled })
	_, err = c.Get("http://example.test", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("transport cancellation lost")
	}
	c.client.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(failingReader{})}, nil
	})
	_, err = c.Get("http://example.test", nil)
	assertTransportCode(t, err, constants.ResponseTruncated, 200)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func assertTransportCode(t *testing.T, err error, code string, status int) {
	t.Helper()
	var target *coreerrors.HttpError
	if !errors.As(err, &target) || target.ErrorCode() != code || target.StatusCode != status {
		t.Fatalf("unexpected transport classification: %v; want %s/%d", err, code, status)
	}
}

func TestSafeHTTPErrorClassifications(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		reading bool
		code    string
	}{
		{"cancel", context.Canceled, false, constants.ClientError},
		{"deadline", context.DeadlineExceeded, false, constants.ConnectTimeOut},
		{"read deadline", context.DeadlineExceeded, true, constants.ReadTimeOut},
		{"truncated", io.ErrUnexpectedEOF, true, constants.ResponseTruncated},
		{"reset", syscall.ECONNRESET, true, constants.ConnectionReset},
		{"broken pipe", syscall.EPIPE, false, constants.ConnectionReset},
		{"certificate", x509.UnknownAuthorityError{}, false, constants.TlsHandshakeFailed},
		{"invalid certificate", x509.CertificateInvalidError{}, false, constants.TlsHandshakeFailed},
		{"hostname", x509.HostnameError{}, false, constants.TlsHandshakeFailed},
		{"TLS record", tls.RecordHeaderError{}, false, constants.TlsHandshakeFailed},
		{"DNS", &net.DNSError{Err: "synthetic"}, false, constants.DnsLookupFailed},
		{"timeout", &net.DNSError{IsTimeout: true}, false, constants.DnsLookupFailed},
		{"network timeout", &net.OpError{Op: "read", Err: syscall.ETIMEDOUT}, false, constants.ConnectTimeOut},
		{"read timeout", &net.OpError{Op: "read", Err: syscall.ETIMEDOUT}, true, constants.ReadTimeOut},
		{"other", errors.New("synthetic"), true, constants.ClientError},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := pamTransportError(test.err, 503, test.reading)
			assertTransportCode(t, err, test.code, 503)
			if !errors.Is(err, test.err) {
				t.Fatal("transport error cause lost")
			}
		})
	}
}

func TestSafeHTTPTimeoutPhases(t *testing.T) {
	for _, phase := range []string{"dial", "headers", "body", "reused connection", "redirect dial"} {
		t.Run(phase, func(t *testing.T) {
			var calls int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := atomic.AddInt32(&calls, 1)
				if phase == "redirect dial" {
					http.Redirect(w, r, "/next", http.StatusTemporaryRedirect)
					return
				}
				if phase == "reused connection" && call == 1 {
					_, _ = io.WriteString(w, `{}`)
					return
				}
				if phase == "body" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			c := newSafeHTTPClient(coreconfig.DefaultHttpConfiguration())
			defer c.CloseIdleConnections()
			transport := c.client.Transport.(*http.Transport)
			transport.ResponseHeaderTimeout = 50 * time.Millisecond
			c.client.Timeout = 2 * time.Second
			if phase == "dial" {
				transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ETIMEDOUT}
				}
			}
			if phase == "redirect dial" {
				transport.DisableKeepAlives = true
				var attempts int32
				dialer := &net.Dialer{Timeout: time.Second}
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					if atomic.AddInt32(&attempts, 1) > 1 {
						return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ETIMEDOUT}
					}
					return dialer.DialContext(ctx, network, address)
				}
			}
			if phase == "reused connection" {
				if _, err := c.Get(server.URL, nil); err != nil {
					t.Fatal(err)
				}
			}
			var gotConnection, reused int32
			ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) {
					atomic.StoreInt32(&gotConnection, 1)
					if info.Reused {
						atomic.StoreInt32(&reused, 1)
					}
				},
			})
			if phase == "body" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			_, err := c.ExecuteContext(ctx, &domain.HttpRequest{Method: enums.HttpMethodGet, URL: server.URL})
			code, status := constants.ReadTimeOut, 0
			if phase == "dial" || phase == "redirect dial" {
				code = constants.ConnectTimeOut
			} else if atomic.LoadInt32(&gotConnection) != 1 {
				t.Fatal("request did not obtain a connection or lost the caller's trace")
			}
			if phase == "body" {
				status = http.StatusOK
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("body deadline cause was lost")
				}
			}
			assertTransportCode(t, err, code, status)
			if phase == "reused connection" && atomic.LoadInt32(&reused) != 1 {
				t.Fatal("control request did not reuse its connection")
			}
		})
	}
}

func TestSafeHTTPRedirectOriginBoundaries(t *testing.T) {
	parse := func(value string) *url.URL {
		u, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	for _, test := range []struct {
		original, target string
		allowed          bool
	}{
		{"https://example.test/start", "https://EXAMPLE.test:443/end", true},
		{"http://example.test/start", "http://example.test:80/end", true},
		{"https://example.test/start", "http://example.test/end", false},
		{"http://example.test/start", "https://example.test/end", false},
		{"https://example.test/start", "https://example.test:444/end", false},
		{"https://example.test/start", "https://other.test/end", false},
		{"https://example.test/start", "https://user:password@example.test/end", false},
	} {
		err := checkPAMRedirect(&http.Request{URL: parse(test.target)}, []*http.Request{{URL: parse(test.original)}})
		if (err == nil) != test.allowed {
			t.Fatalf("origin policy mismatch for %s -> %s", test.original, test.target)
		}
	}
	if err := checkPAMRedirect(&http.Request{}, make([]*http.Request, 5)); err == nil {
		t.Fatal("redirect limit not enforced")
	}
	if err := checkPAMRedirect(&http.Request{}, nil); err != nil {
		t.Fatal(err)
	}
}
