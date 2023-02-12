// Copyright 2023 Meraj Sahebdar
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package argon2_test

import (
	"testing"

	"github.com/merajsahebdar/argon2"
)

func TestArgon2Decoder(t *testing.T) {
	testCases := []struct {
		args string
		want string
	}{
		{
			"$argon2id$v=19$m=65536,t=3,p=2$WDlCUU15WlF4OFNGd3d6OA$0nJpNUfEq3ELzeoGwcd+cG4er9wu3DgYCBJb2w3nnI8",
			"password",
		},
		{
			"$argon2id$v=19$m=65536,t=3,p=2$WDlCUU15WlF4OFNGd3d6OA$parPWxJrAJEdk57bpMuCC/kLhKJV4EnMb8205SNrFUQ",
			"secret",
		},
	}

	for idx, testCase := range testCases {
		if a, err := argon2.NewByEncoded(testCase.args); err != nil {
			t.Errorf("in case %d failed to decode: %s", idx, err)
		} else {
			if ok := a.Compare(testCase.want); !ok {
				t.Errorf("in case %d failed to match", idx)
			}
		}
	}
}

func TestArgon2SQLValuer(t *testing.T) {
	testCases := []struct {
		args string
	}{
		{"password"},
		{"secret"},
	}

	for idx, testCase := range testCases {
		a := argon2.MustNew(testCase.args)

		if v, err := a.Value(); err != nil {
			t.Errorf("in case %d error is not expected", idx)
		} else {
			if x, ok := v.(string); !ok || x == "" {
				t.Errorf("in case %d got invalid return value", idx)
			} else {
				t.Logf("got return value %s", x)
			}
		}
	}
}

func TestArgon2SQLScanner(t *testing.T) {
	testCases := []struct {
		args string
		want string
	}{
		{
			"$argon2id$v=19$m=65536,t=3,p=2$WDlCUU15WlF4OFNGd3d6OA$0nJpNUfEq3ELzeoGwcd+cG4er9wu3DgYCBJb2w3nnI8",
			"password",
		},
		{
			"$argon2id$v=19$m=65536,t=3,p=2$WDlCUU15WlF4OFNGd3d6OA$parPWxJrAJEdk57bpMuCC/kLhKJV4EnMb8205SNrFUQ",
			"secret",
		},
	}

	for idx, testCase := range testCases {
		a := &argon2.Argon2{}

		if err := a.Scan(testCase.args); err != nil {
			t.Errorf("in case %d failed to decode: %s", idx, err)
		} else {
			if ok := a.Compare(testCase.want); !ok {
				t.Errorf("in case %d failed to match", idx)
			}
		}
	}
}
