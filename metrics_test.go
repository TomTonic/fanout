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
	"time"

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
	requestCancelMetricName   = "coredns_fanout_request_cancel_count_total"
	requestSuccessMetricName  = "coredns_fanout_request_success_count_total"
	responseWinMetricName     = "coredns_fanout_response_win_count_total"
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
	attempts        float64
	totalErrors     float64
	errorCount      float64
	cancelCount     float64
	successCount    float64
	winCount        float64
	rcodeCount      float64
	durationCount   uint64
	totalRcodeCount float64
}

type metricsClientStub struct {
	endpoint string
	network  string
	request  func(context.Context, *request.Request) (*dns.Msg, error)
}

func (c metricsClientStub) Request(ctx context.Context, req *request.Request) (*dns.Msg, error) {
	return c.request(ctx, req)
}

func (c metricsClientStub) Endpoint() string {
	return c.endpoint
}

func (c metricsClientStub) Net() string {
	return c.network
}

func (c metricsClientStub) SetTLSConfig(*tls.Config) {}

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
	require.Equal(t, before.totalErrors+1, after.totalErrors)
	require.Equal(t, before.cancelCount, after.cancelCount)
	require.Equal(t, before.successCount, after.successCount)
	require.Equal(t, before.winCount, after.winCount)
	require.Equal(t, before.rcodeCount, after.rcodeCount)
	require.Equal(t, before.durationCount, after.durationCount)
	assertRequestOutcomeInvariant(t, before, after)
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
	require.Equal(t, before.totalErrors, after.totalErrors)
	require.Equal(t, before.cancelCount, after.cancelCount)
	require.Equal(t, before.successCount+1, after.successCount)
	require.Equal(t, before.winCount, after.winCount)
	require.Equal(t, before.rcodeCount+1, after.rcodeCount)
	require.Equal(t, before.durationCount+1, after.durationCount)
	require.Equal(t, before.totalRcodeCount+1, after.totalRcodeCount)
	assertRequestOutcomeInvariant(t, before, after)
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
	require.Equal(t, before.totalErrors+1, after.totalErrors)
	require.Equal(t, before.cancelCount, after.cancelCount)
	require.Equal(t, before.successCount, after.successCount)
	require.Equal(t, before.winCount, after.winCount)
	require.Equal(t, before.rcodeCount, after.rcodeCount)
	require.Equal(t, before.durationCount, after.durationCount)
	assertRequestOutcomeInvariant(t, before, after)

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
	require.Equal(t, before.totalErrors+1, after.totalErrors)
	require.Equal(t, before.cancelCount, after.cancelCount)
	require.Equal(t, before.successCount, after.successCount)
	require.Equal(t, before.winCount, after.winCount)
	require.Equal(t, before.rcodeCount, after.rcodeCount)
	require.Equal(t, before.durationCount, after.durationCount)
	assertRequestOutcomeInvariant(t, before, after)

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
	require.Equal(t, before.totalErrors, after.totalErrors)
	require.Equal(t, before.cancelCount+1, after.cancelCount)
	require.Equal(t, before.successCount, after.successCount)
	require.Equal(t, before.winCount, after.winCount)
	require.Equal(t, before.rcodeCount, after.rcodeCount)
	require.Equal(t, before.durationCount, after.durationCount)
	assertRequestOutcomeInvariant(t, before, after)
}

// TestServeDNSRequestMetricsTrackWins verifies that a selected upstream response increments
// both the successful request outcome and the downstream win counter for that upstream.
func TestServeDNSRequestMetricsTrackWins(t *testing.T) {
	const endpoint = "metrics-win.invalid:53"
	before := snapshotMetrics(t, endpoint, requestErrorProtocol, dns.RcodeToString[dns.RcodeSuccess])

	f := New()
	f.From = "."
	f.Attempts = 1
	f.WorkerCount = 1
	f.AddClient(metricsClientStub{
		endpoint: endpoint,
		network:  UDP,
		request: func(_ context.Context, req *request.Request) (*dns.Msg, error) {
			observeRequestAttempt(endpoint)
			resp := new(dns.Msg)
			resp.SetReply(req.Req)
			observeRequestResponse(endpoint, time.Now(), resp)
			return resp, nil
		},
	})

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	rcode, err := f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
	require.NoError(t, err)
	require.Equal(t, 0, rcode)

	after := snapshotMetrics(t, endpoint, requestErrorProtocol, dns.RcodeToString[dns.RcodeSuccess])
	require.Equal(t, before.attempts+1, after.attempts)
	require.Equal(t, before.totalErrors, after.totalErrors)
	require.Equal(t, before.cancelCount, after.cancelCount)
	require.Equal(t, before.successCount+1, after.successCount)
	require.Equal(t, before.winCount+1, after.winCount)
	require.Equal(t, before.rcodeCount+1, after.rcodeCount)
	require.Equal(t, before.durationCount+1, after.durationCount)
	require.Equal(t, before.totalRcodeCount+1, after.totalRcodeCount)
	assertRequestOutcomeInvariant(t, before, after)
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
		attempts:        counterValue(t, requestCountMetricName, map[string]string{"to": endpoint}),
		totalErrors:     sumCounterValues(t, requestErrorMetricName, map[string]string{"to": endpoint}),
		errorCount:      counterValue(t, requestErrorMetricName, map[string]string{"to": endpoint, "error": string(errClass)}),
		cancelCount:     counterValue(t, requestCancelMetricName, map[string]string{"to": endpoint}),
		successCount:    counterValue(t, requestSuccessMetricName, map[string]string{"to": endpoint}),
		winCount:        counterValue(t, responseWinMetricName, map[string]string{"to": endpoint}),
		rcodeCount:      counterValue(t, rcodeCountMetricName, map[string]string{"to": endpoint, "rcode": rcode}),
		durationCount:   histogramCount(t, requestDurationMetricName, map[string]string{"to": endpoint}),
		totalRcodeCount: sumCounterValues(t, rcodeCountMetricName, map[string]string{"to": endpoint}),
	}
}

func assertRequestOutcomeInvariant(t *testing.T, before, after metricsSnapshot) {
	t.Helper()
	attemptDelta := after.attempts - before.attempts
	errorDelta := after.totalErrors - before.totalErrors
	cancelDelta := after.cancelCount - before.cancelCount
	successDelta := after.successCount - before.successCount
	require.Equal(t, attemptDelta, errorDelta+cancelDelta+successDelta)
	require.Equal(t, successDelta, after.totalRcodeCount-before.totalRcodeCount)
	require.GreaterOrEqual(t, successDelta, after.winCount-before.winCount)
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

func sumCounterValues(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		var total float64
		for _, metric := range family.GetMetric() {
			if !metricHasLabels(metric, labels) || metric.Counter == nil {
				continue
			}
			total += metric.GetCounter().GetValue()
		}
		return total
	}
	return 0
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

func metricHasLabels(metric *dto.Metric, expected map[string]string) bool {
	for key, value := range expected {
		matched := false
		for _, label := range metric.GetLabel() {
			if label.GetName() == key && label.GetValue() == value {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
