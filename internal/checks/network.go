package checks

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

const (
	dialTimeout = 3 * time.Second
	maxBodySize = 1 << 20
)

// port probes a port from the checker.
func port(ctx context.Context, host string, c *v1alpha1.PortCheck) (sdk.Result, error) {
	if c.Protocol != v1alpha1.ProtocolTCP {
		return sdk.Result{}, fmt.Errorf("port: protocol %s: %w", c.Protocol, ErrUnsupported)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(c.Port)))
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	open := err == nil
	if open {
		_ = conn.Close()
	}

	switch {
	case open && c.Expect == v1alpha1.PortOpen:
		return sdk.Pass(fmt.Sprintf("port %d is open", c.Port)), nil
	case !open && c.Expect == v1alpha1.PortClosed:
		return sdk.Pass(fmt.Sprintf("port %d is closed", c.Port)), nil
	case open:
		return sdk.Fail(fmt.Sprintf("port %d is still open", c.Port)), nil
	default:
		return sdk.Fail(fmt.Sprintf("port %d is not reachable", c.Port)), nil
	}
}

// httpCheck sends a GET request from the checker.
func httpCheck(ctx context.Context, host string, c *v1alpha1.HTTPCheck) (sdk.Result, error) {
	url := fmt.Sprintf("%s://%s%s", c.Scheme, net.JoinHostPort(host, strconv.Itoa(int(c.Port))), c.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// Student services commonly use self-signed certificates: the
			// check is about behavior, not about the certificate chain.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return sdk.Result{}, err
		}
		return sdk.Fail(fmt.Sprintf("GET %s failed: %v", c.Path, err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != int(c.ExpectStatus) {
		return sdk.Fail(fmt.Sprintf("GET %s returned %d, expected %d", c.Path, resp.StatusCode, c.ExpectStatus)), nil
	}
	if c.ExpectBody != "" {
		re, err := regexp.Compile(c.ExpectBody)
		if err != nil {
			return sdk.Result{}, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			return sdk.Fail(fmt.Sprintf("reading GET %s: %v", c.Path, err)), nil
		}
		if !re.Match(body) {
			return sdk.Fail(fmt.Sprintf("GET %s: the response does not match %q", c.Path, c.ExpectBody)), nil
		}
	}
	return sdk.Pass(fmt.Sprintf("GET %s returned %d", c.Path, resp.StatusCode)), nil
}
