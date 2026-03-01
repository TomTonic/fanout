// Copyright (c) 2024 MWS and/or its affiliates.
// Copyright (c) 2026 Tom Gelhausen; contributors: various coding‑agents.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package selector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestWeightedRand_Pick verifies the WeightedRand selector picks elements without replacement.
// Since rand/v2 uses a non-seedable global source, we verify set membership rather than order.
func TestWeightedRand_Pick(t *testing.T) {
	testCases := map[string]struct {
		values  []string
		weights []int
		picks   int
		excess  int // picks beyond len(values) that should return ""
	}{
		"all_same_weight":      {[]string{"a", "b", "c", "d", "e"}, []int{100, 100, 100, 100, 100}, 5, 0},
		"all_different_weight": {[]string{"a", "b", "c"}, []int{100, 70, 10}, 3, 0},
		"pick_some":            {[]string{"a", "b", "c", "d", "e"}, []int{100, 100, 100, 100, 100}, 3, 0},
		"more_than_available":  {[]string{"a", "b", "c"}, []int{70, 10, 100}, 4, 1},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			wrs := NewWeightedRandSelector(tc.values, tc.weights)
			picked, defaults := pickAll(wrs, tc.picks)
			allowed := make(map[string]bool, len(tc.values))
			for _, v := range tc.values {
				allowed[v] = true
			}
			for v := range picked {
				assert.True(t, allowed[v], "picked value %q not in expected set", v)
			}
			assert.Equal(t, tc.picks-tc.excess, len(picked), "unexpected unique picks")
			assert.Equal(t, tc.excess, defaults, "unexpected default picks")
		})
	}
}

// pickAll picks n elements from the selector, returning unique non-empty values and the count of empty (default) picks.
func pickAll(wrs *WeightedRand[string], n int) (picked map[string]bool, defaults int) {
	picked = make(map[string]bool)
	for i := 0; i < n; i++ {
		if v := wrs.Pick(); v == "" {
			defaults++
		} else {
			picked[v] = true
		}
	}
	return picked, defaults
}
