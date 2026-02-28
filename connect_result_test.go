package fanout

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// TestIsBetter verifies the response-ranking logic used when the fanout plugin collects answers
// from multiple upstream servers concurrently. isBetter(left, right) decides whether right is a
// better result than left: success beats error, error beats nil, NXDOMAIN loses to success.
// This table-driven test covers 16 combinations of nil, error, nil-message, NXDOMAIN, and success
// responses, ensuring the plugin always selects the most useful answer to return to the client.
//
//nolint:funlen // table-driven permutations are kept in one place for readability
func TestIsBetter(t *testing.T) {
	okResponse := &response{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}},
	}
	nxResponse := &response{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}},
	}
	errResponse := &response{
		err: errors.New("connection refused"),
	}
	nilMsgResponse := &response{
		response: nil,
	}

	tests := []struct {
		name     string
		left     *response
		right    *response
		expected bool
	}{
		{
			name:     "both_nil",
			left:     nil,
			right:    nil,
			expected: false,
		},
		{
			name:     "right_nil",
			left:     okResponse,
			right:    nil,
			expected: false,
		},
		{
			name:     "left_nil_right_ok",
			left:     nil,
			right:    okResponse,
			expected: true,
		},
		{
			name:     "left_nil_right_err",
			left:     nil,
			right:    errResponse,
			expected: true,
		},
		{
			name:     "left_err_right_ok",
			left:     errResponse,
			right:    okResponse,
			expected: true,
		},
		{
			name:     "left_ok_right_err",
			left:     okResponse,
			right:    errResponse,
			expected: false,
		},
		{
			name:     "both_err",
			left:     errResponse,
			right:    &response{err: errors.New("other error")},
			expected: false,
		},
		{
			name:     "left_ok_right_nil_msg",
			left:     okResponse,
			right:    nilMsgResponse,
			expected: false,
		},
		{
			name:     "left_nil_msg_right_ok",
			left:     nilMsgResponse,
			right:    okResponse,
			expected: true,
		},
		{
			name:     "left_nil_msg_right_nil_msg",
			left:     nilMsgResponse,
			right:    nilMsgResponse,
			expected: false,
		},
		{
			name:     "left_nxdomain_right_ok",
			left:     nxResponse,
			right:    okResponse,
			expected: true,
		},
		{
			name:     "left_ok_right_nxdomain",
			left:     okResponse,
			right:    nxResponse,
			expected: false,
		},
		{
			name:     "both_ok",
			left:     okResponse,
			right:    okResponse,
			expected: false,
		},
		{
			name:     "both_nxdomain",
			left:     nxResponse,
			right:    nxResponse,
			expected: false,
		},
		{
			name:     "left_err_right_nil_msg",
			left:     errResponse,
			right:    nilMsgResponse,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isBetter(tc.left, tc.right))
		})
	}
}
