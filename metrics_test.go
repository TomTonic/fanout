// Copyright (c) 2026 Tom Gelhausen; contributors: various coding-agents.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fanout

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

const (
	requestCountMetricName    = "coredns_fanout_request_count_total"
	requestErrorMetricName    = "coredns_fanout_request_error_count_total"
	rcodeCountMetricName      = "coredns_fanout_response_rcode_count_total"
	requestDurationMetricName = "coredns_fanout_request_duration_seconds"
)

type fakeTransport struct {
	dialFunc      func(context.Context, string) (*dns.Conn, error)
	yieldFunc     func(*dns.Conn)
	setTLSCfgFunc func(*tls.Config)
	closeFunc     func()
}

func (f fakeTransport) Dial(ctx context.Context, network string) (*dns.Conn, error) {
	return f.dialFunc(ctx, network)
}

func (f fakeTransport) Yield(conn *dns.Conn) {
	if f.yieldFunc != nil {
		f.yieldFunc(conn)
	}
}

func (f fakeTransport) SetTLSConfig(cfg *tls.Config) {
	if f.setTLSCfgFunc != nil {
		f.setTLSCfgFunc(cfg)
	}
}

func (f fakeTransport) Close() {
	if f.closeFunc != nil {
		f.closeFunc()
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type metricsSnapshot struct {
	attempts      float64
	errorCount    float64
	rcodeCount    float64
	durationCount uint64
}

// TestClientRequestMetricsOnDialFailure verifies that a failed upstream connection attempt
// increments the request attempt counter and the bounded connect_failed counter without
// producing a response code or duration sample.
func TestClientRequestMetricsOnDialFailure(t *testing.T) {
	const endpoint = "metrics.invalid:53"
	before := snapshotMetrics(t, endpoint, requestErrorConnect, dns.RcodeToString[dns.RcodeSuccess])

	c := &client{
		transport: fakeTransport{
			dialFunc: func(context.Context, string) (*dns.Conn, error) {
				return nil, errors.New("dial failed")
			},
		},
		addr: endpoint,
		net:  "udp",
	}

	_, err := c.Request(context.Background(), newTestRequest())
	require.Error(t, err)

	after := snapshotMetrics(t, endpoint, requestErrorConnect, dns.RcodeToString[dns.RcodeSuccess])
	require.Equal(t, before.attempts+1, after.attempts)
	require.Equal(t, before.errorCount+1, after.errorCount)
	require.Equal(t, before.rcodeCount, after.rcodeCount)
	require.Equal(t, before.durationCount, after.durationCount)
}

// TestDoHRequestMetricsOnSuccess verifies that a successful DoH request increments the
// request attempt counter, records the returned RCODE, and observes duration without
// incrementing the bounded error counter.
func TestDoHRequestMetricsOnSuccess(t *testing.T) {
	const endpoint = "https://metrics.example/dns-query"
	req := newTestRequest()
	before := snapshotMetrics(t, endpoint, requestErrorResponseRead, dns.RcodeToString[dns.RcodeSuccess])

	httpClient := &http.Client{Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		body := mustPackReply(t, req.Req, dns.RcodeSuccess)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{dohContentType}},
			Body:       io.NopCloser(bytes.NewReader(body)),
		}, nil
	})}

	resp, err := dohRoundTrip(context.Background(), httpClient, endpoint, req)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)

	after := snapshotMetrics(t, endpoint, requestErrorResponseRead, dns.RcodeToString[dns.RcodeSuccess])
	require.Equal(t, before.attempts+1, after.attempts)
	require.Equal(t, before.errorCount, after.errorCount)
	require.Equal(t, before.rcodeCount+1, after.rcodeCount)
	require.Equal(t, before.durationCount+1, after.durationCount)
}

// TestDoHRequestMetricsOnHTTPStatusFailure verifies that a DoH HTTP error increments the
// request attempt counter and the bounded response_status_invalid counter, while leaving
// response and duration metrics unchanged.
func TestDoHRequestMetricsOnHTTPStatusFailure(t *testing.T) {
	const endpoint = "https://metrics.example/status"
	before := snapshotMetrics(t, endpoint, requestErrorResponseStatus, dns.RcodeToString[dns.RcodeSuccess])

	httpClient := &http.Client{Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     http.Header{"Content-Type": []string{dohContentType}},
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}, nil
	})}

	_, err := dohRoundTrip(context.Background(), httpClient, endpoint, newTestRequest())
	require.Error(t, err)

	after := snapshotMetrics(t, endpoint, requestErrorResponseStatus, dns.RcodeToString[dns.RcodeSuccess])
	require.Equal(t, before.attempts+1, after.attempts)
	require.Equal(t, before.errorCount+1, after.errorCount)
	require.Equal(t, before.rcodeCount, after.rcodeCount)
	require.Equal(t, before.durationCount, after.durationCount)

	unexpectedLabelValue := counterValue(t, requestErrorMetricName, map[string]string{"to": endpoint, "error": "HTTP 502"})
	require.Zero(t, unexpectedLabelValue)
}

// TestDoHRequestMetricsOnContentTypeFailure verifies that fanout records the normalized
// response_content_type_invalid class instead of propagating raw content-type values into labels.
func TestDoHRequestMetricsOnContentTypeFailure(t *testing.T) {
	const endpoint = "https://metrics.example/content-type"
	before := snapshotMetrics(t, endpoint, requestErrorResponseContentType, dns.RcodeToString[dns.RcodeSuccess])

	httpClient := &http.Client{Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}, nil
	})}

	_, err := dohRoundTrip(context.Background(), httpClient, endpoint, newTestRequest())
	require.Error(t, err)

	after := snapshotMetrics(t, endpoint, requestErrorResponseContentType, dns.RcodeToString[dns.RcodeSuccess])
	require.Equal(t, before.attempts+1, after.attempts)
	require.Equal(t, before.errorCount+1, after.errorCount)
	require.Equal(t, before.rcodeCount, after.rcodeCount)
	require.Equal(t, before.durationCount, after.durationCount)

	unexpectedLabelValue := counterValue(t, requestErrorMetricName, map[string]string{"to": endpoint, "error": "unexpected content-type \"text/plain\""})
	require.Zero(t, unexpectedLabelValue)
}

// TestDoHRequestMetricsIgnoreLocalCancellation verifies that a locally cancelled request
// still counts as an attempt but does not inflate upstream error counters.
func TestDoHRequestMetricsIgnoreLocalCancellation(t *testing.T) {
	const endpoint = "https://metrics.example/cancelled"
	before := snapshotMetrics(t, endpoint, requestErrorRequestSend, dns.RcodeToString[dns.RcodeSuccess])

	ctx, cancel := context.WithCancel(context.Background())
	httpClient := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	cancel()

	_, err := dohRoundTrip(ctx, httpClient, endpoint, newTestRequest())
	require.ErrorIs(t, err, context.Canceled)

	after := snapshotMetrics(t, endpoint, requestErrorRequestSend, dns.RcodeToString[dns.RcodeSuccess])
	require.Equal(t, before.attempts+1, after.attempts)
	require.Equal(t, before.errorCount, after.errorCount)
	require.Equal(t, before.rcodeCount, after.rcodeCount)
	require.Equal(t, before.durationCount, after.durationCount)
}

func newTestRequest() *request.Request {
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	return &request.Request{W: &test.ResponseWriter{}, Req: req}
}

func mustPackReply(t *testing.T, req *dns.Msg, rcode int) []byte {
	t.Helper()
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = rcode
	packed, err := resp.Pack()
	require.NoError(t, err)
	return packed
}

func snapshotMetrics(t *testing.T, endpoint string, errClass requestErrorClass, rcode string) metricsSnapshot {
	t.Helper()
	return metricsSnapshot{
		attempts:      counterValue(t, requestCountMetricName, map[string]string{"to": endpoint}),
		errorCount:    counterValue(t, requestErrorMetricName, map[string]string{"to": endpoint, "error": string(errClass)}),
		rcodeCount:    counterValue(t, rcodeCountMetricName, map[string]string{"to": endpoint, "rcode": rcode}),
		durationCount: histogramCount(t, requestDurationMetricName, map[string]string{"to": endpoint}),
	}
}

func counterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	metric := findMetric(t, name, labels)
	if metric == nil || metric.Counter == nil {
		return 0
	}
	return metric.GetCounter().GetValue()
}

func histogramCount(t *testing.T, name string, labels map[string]string) uint64 {
	t.Helper()
	metric := findMetric(t, name, labels)
	if metric == nil || metric.Histogram == nil {
		return 0
	}
	return metric.GetHistogram().GetSampleCount()
}

func findMetric(t *testing.T, name string, labels map[string]string) *dto.Metric {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricLabelsMatch(metric, labels) {
				return metric
			}
		}
	}
	return nil
}

func metricLabelsMatch(metric *dto.Metric, expected map[string]string) bool {
	if len(metric.GetLabel()) != len(expected) {
		return false
	}
	for _, label := range metric.GetLabel() {
		if expected[label.GetName()] != label.GetValue() {
			return false
		}
	}
	return true
}
