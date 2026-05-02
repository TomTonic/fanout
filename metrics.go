// Copyright (c) 2020 Doc.ai and/or its affiliates.
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
	"context"
	"fmt"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricLabelTo    = "to"
	metricLabelError = "error"
	metricLabelRcode = "rcode"
)

type requestErrorClass string

const (
	requestErrorConnect             requestErrorClass = "connect_failed"
	requestErrorReconnect           requestErrorClass = "reconnect_failed"
	requestErrorStreamOpen          requestErrorClass = "stream_open_failed"
	requestErrorRequestEncode       requestErrorClass = "request_encode_failed"
	requestErrorRequestBuild        requestErrorClass = "request_build_failed"
	requestErrorRequestSend         requestErrorClass = "request_send_failed"
	requestErrorResponseStatus      requestErrorClass = "response_status_invalid"
	requestErrorResponseContentType requestErrorClass = "response_content_type_invalid"
	requestErrorResponseRead        requestErrorClass = "response_read_failed"
	requestErrorResponseDecode      requestErrorClass = "response_decode_failed"
	requestErrorProtocol            requestErrorClass = "protocol_error"
)

// Variables declared for monitoring.
var (
	RequestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "request_count_total",
		Help:      "Number of request attempts started per upstream.",
	}, []string{metricLabelTo})
	ErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "request_error_count_total",
		Help:      "Number of request attempts that ended with an upstream error, grouped by bounded error class.",
	}, []string{metricLabelError, metricLabelTo})
	CancelCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "request_cancel_count_total",
		Help:      "Number of request attempts that were canceled locally before a final upstream outcome was received.",
	}, []string{metricLabelTo})
	SuccessCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "request_success_count_total",
		Help:      "Number of request attempts that completed with a valid DNS response per upstream.",
	}, []string{metricLabelTo})
	WinCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "response_win_count_total",
		Help:      "Number of selected upstream responses that fanout returned downstream per upstream.",
	}, []string{metricLabelTo})
	RcodeCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "response_rcode_count_total",
		Help:      "Number of responses per response code per upstream.",
	}, []string{metricLabelRcode, metricLabelTo})
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "request_duration_seconds",
		Buckets:   plugin.TimeBuckets,
		Help:      "Histogram of the time request attempts with a valid DNS response took.",
	}, []string{"to"})
)

type requestMetricError struct {
	class requestErrorClass
	err   error
}

func (e *requestMetricError) Error() string {
	return e.err.Error()
}

func (e *requestMetricError) Unwrap() error {
	return e.err
}

func observeRequestAttempt(to string) {
	RequestCount.WithLabelValues(to).Inc()
}

func observeRequestError(to string, class requestErrorClass) {
	ErrorCount.WithLabelValues(string(class), to).Inc()
}

func observeRequestCancellation(to string) {
	CancelCount.WithLabelValues(to).Inc()
}

func observeRequestWin(to string) {
	WinCount.WithLabelValues(to).Inc()
}

func observeRequestResponse(to string, start time.Time, resp *dns.Msg) {
	SuccessCount.WithLabelValues(to).Inc()
	RcodeCount.WithLabelValues(rcodeLabel(resp.Rcode), to).Inc()
	RequestDuration.WithLabelValues(to).Observe(time.Since(start).Seconds())
}

func rcodeLabel(rcode int) string {
	if rc, ok := dns.RcodeToString[rcode]; ok {
		return rc
	}
	return fmt.Sprint(rcode)
}

func withRequestErrorClass(err error, class requestErrorClass) error {
	if err == nil {
		return nil
	}
	return &requestMetricError{class: class, err: err}
}

func requestErrorClassOf(err error) requestErrorClass {
	var metricErr *requestMetricError
	if errors.As(err, &metricErr) {
		return metricErr.class
	}
	return requestErrorProtocol
}

func shouldSuppressRequestFailure(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	return errors.Is(ctx.Err(), context.Canceled)
}

func suppressedRequestFailure(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return err
}

func observeSuppressedRequestFailure(ctx context.Context, to string, err error) error {
	observeRequestCancellation(to)
	return suppressedRequestFailure(ctx, err)
}
