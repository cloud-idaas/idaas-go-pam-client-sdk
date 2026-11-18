package pam

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	coreconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	corehttp "github.com/cloud-idaas/idaas-go-core-sdk/http"
)

const maxPAMResponseBytes = 4 << 20

// safeHTTPClient owns only PAM Developer API traffic. Endpoint hosts come from
// trusted host configuration. Core provider traffic and injected clients remain
// outside this transport's ownership and redirect policy.
type safeHTTPClient struct{ client *http.Client }

var _ corehttp.HttpClient = (*safeHTTPClient)(nil)
var _ corehttp.ResourceCloser = (*safeHTTPClient)(nil)

func newSafeHTTPClient(cfg *coreconfig.HttpConfiguration) *safeHTTPClient {
	readTimeout := time.Duration(cfg.ReadTimeout) * time.Millisecond
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: time.Duration(cfg.ConnectTimeout) * time.Millisecond, KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: readTimeout,
		ExpectContinueTimeout: time.Second, IdleConnTimeout: 90 * time.Second,
		MaxIdleConns: 100, MaxIdleConnsPerHost: 10, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.UnsafeIgnoreSSLCert}, // #nosec G402 -- explicit caller option, matching Core configuration.
	}
	return &safeHTTPClient{client: &http.Client{
		Timeout: readTimeout, Transport: transport, CheckRedirect: checkPAMRedirect,
	}}
}

func checkPAMRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("PAM redirect limit exceeded")
	}
	// Enforce the documented origin policy against the initial request.
	if len(via) > 0 {
		original := via[0].URL
		if req.URL.User != nil || !strings.EqualFold(req.URL.Scheme, original.Scheme) ||
			!strings.EqualFold(req.URL.Hostname(), original.Hostname()) || originPort(req.URL) != originPort(original) {
			return errors.New("PAM cross-origin redirect rejected")
		}
	}
	return nil
}

func originPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func (c *safeHTTPClient) Execute(request *domain.HttpRequest) (*domain.HttpResponse, error) {
	return c.ExecuteContext(context.Background(), request)
}

func (c *safeHTTPClient) ExecuteContext(ctx context.Context, request *domain.HttpRequest) (*domain.HttpResponse, error) {
	u, err := url.Parse(request.URL)
	if err != nil {
		return nil, coreerrors.NewHttpError(constants.InvalidURL, "Invalid PAM request URL", 0, nil)
	}
	query := u.Query()
	for name, values := range request.QueryParams {
		for _, value := range values {
			query.Add(name, value)
		}
	}
	u.RawQuery = query.Encode()
	var body io.Reader
	if request.Body != nil {
		encoded, err := json.Marshal(request.Body)
		if err != nil {
			return nil, coreerrors.NewEncodingError(constants.EncodeFailed, "PAM body must be JSON encodable", nil)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, string(request.Method), u.String(), body)
	if err != nil {
		return nil, coreerrors.NewHttpError(constants.ClientError, "Invalid PAM HTTP request", 0, nil)
	}
	req.Header.Set(constants.HeaderUserAgent, corehttp.BuildUserAgent())
	for name, value := range request.Headers {
		req.Header.Set(name, value)
	}
	if request.ContentType == enums.ContentTypeJson {
		req.Header.Set(constants.HeaderContentType, constants.ContentTypeJson)
	}
	// Do also waits for response headers. Classify timeouts after a connection
	// is obtained as read timeouts, including pooled connections. Redirects
	// start a new connection phase; trace callbacks may run concurrently.
	var connected int32
	trace := &httptrace.ClientTrace{
		GetConn: func(string) { atomic.StoreInt32(&connected, 0) },
		GotConn: func(httptrace.GotConnInfo) { atomic.StoreInt32(&connected, 1) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, pamTransportError(err, 0, atomic.LoadInt32(&connected) == 1)
	}
	defer resp.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, maxPAMResponseBytes+1))
	if err != nil {
		return nil, pamTransportError(err, resp.StatusCode, true)
	}
	if len(encoded) > maxPAMResponseBytes {
		return nil, coreerrors.NewHttpError(constants.ResponseTooLarge, "PAM response exceeds 4 MiB", resp.StatusCode, nil)
	}
	return &domain.HttpResponse{StatusCode: resp.StatusCode, Headers: resp.Header, Body: encoded}, nil
}

func (c *safeHTTPClient) Get(rawURL string, headers map[string]string) (*domain.HttpResponse, error) {
	return c.Execute(&domain.HttpRequest{Method: enums.HttpMethodGet, URL: rawURL, Headers: headers})
}

func (c *safeHTTPClient) Post(rawURL string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	return c.Execute(&domain.HttpRequest{Method: enums.HttpMethodPost, URL: rawURL, Headers: headers, Body: body, ContentType: enums.ContentTypeJson})
}

func (c *safeHTTPClient) CloseIdleConnections() { c.client.CloseIdleConnections() }

// Preserve Core's actionable transport codes and the original transport cause.
func pamTransportError(err error, status int, reading bool) error {
	code := constants.ClientError
	timeoutCode := constants.ConnectTimeOut
	if reading {
		timeoutCode = constants.ReadTimeOut
	}
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var record tls.RecordHeaderError
	var dns *net.DNSError
	var network net.Error
	switch {
	case errors.Is(err, context.Canceled):
	case errors.Is(err, context.DeadlineExceeded):
		code = timeoutCode
	case reading && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)):
		code = constants.ResponseTruncated
	case errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE):
		code = constants.ConnectionReset
	case errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &record):
		code = constants.TlsHandshakeFailed
	case errors.As(err, &dns):
		code = constants.DnsLookupFailed
	case errors.As(err, &network) && network.Timeout():
		code = timeoutCode
	}
	return coreerrors.NewHttpError(code, "PAM HTTP transport failed", status, err)
}
