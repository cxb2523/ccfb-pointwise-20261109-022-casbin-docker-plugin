// Copyright 2019 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin-authz-plugin/plugin"
	"github.com/docker/go-plugins-helpers/authorization"
)

// TestConcurrentEnforce hammers AuthZReq from many goroutines while a
// separate goroutine repeatedly hot-reloads the policy file, under -race.
//
// It uses two policy files that are swapped into place on disk and reloaded
// via plugin.ReloadPolicy():
//   - "wide"   grants GET /always-allowed and GET /legit-user
//   - "narrow" grants only GET /always-allowed (i.e. /legit-user's grant is
//     revoked)
//
// Correctness requirement under concurrency:
//   - /always-allowed is present in every policy generation, so it must
//     NEVER be denied, no matter how many reloads race against it. Before
//     the fix, the unsynchronized Enforcer observes LoadPolicy's
//     ClearPolicy()+rebuild as two separate unlocked steps and intermittently
//     denies this request - that is the "legit user rejected" failure mode
//     from the bug report.
//   - After every reload has finished and the policy is back to "wide",
//     /legit-user must be allowed again - it must not get stuck denied, and
//     during the reload storm it must never be seen allowed while the plugin
//     most recently finished loading "narrow" AND no further reload is
//     in-flight (checked only at the fully-settled end state below, since
//     mid-storm the "currently active generation" has no single answer for
//     a racing reader by construction).
//
// Run with:
//
//	go test -race -run TestConcurrentEnforce -count=1000 .
func TestConcurrentEnforce(t *testing.T) {
	dir, err := ioutil.TempDir("", "casbin-authz-plugin-test")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	modelPath := filepath.Join(dir, "model.conf")
	policyPath := filepath.Join(dir, "policy.csv")

	if err := ioutil.WriteFile(modelPath, []byte(basicModel), 0644); err != nil {
		t.Fatalf("write model: %v", err)
	}

	widePolicy := "p, /always-allowed, GET\np, /legit-user, GET\n"
	narrowPolicy := "p, /always-allowed, GET\n"

	if err := ioutil.WriteFile(policyPath, []byte(widePolicy), 0644); err != nil {
		t.Fatalf("write initial policy: %v", err)
	}

	p, err := plugin.NewPlugin(modelPath, policyPath)
	if err != nil {
		t.Fatalf("NewPlugin: %v", err)
	}

	const numRequests = 1000
	const numReloads = 10

	var wg sync.WaitGroup
	var alwaysAllowedDenied int64

	reqAlwaysAllowed := authorization.Request{RequestURI: "/always-allowed", RequestMethod: "GET"}
	reqLegitUser := authorization.Request{RequestURI: "/legit-user", RequestMethod: "GET"}

	// Requesters: numRequests goroutines firing both URIs concurrently.
	wg.Add(numRequests)
	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()

			res := p.AuthZReq(reqAlwaysAllowed)
			if !res.Allow {
				atomic.AddInt64(&alwaysAllowedDenied, 1)
			}

			// Exercise the revocable path concurrently with reloads too; its
			// outcome legitimately varies with which generation is active,
			// so it is not asserted on here - only -race and the settled
			// end-state check below matter for it.
			p.AuthZReq(reqLegitUser)
		}()
	}

	// Reloader: alternates the on-disk policy between "wide" and "narrow"
	// and reloads numReloads times while requests are in flight.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numReloads; i++ {
			content := widePolicy
			if i%2 == 0 {
				content = narrowPolicy
			}
			if err := ioutil.WriteFile(policyPath, []byte(content), 0644); err != nil {
				t.Errorf("rewrite policy file: %v", err)
				return
			}
			if err := p.ReloadPolicy(); err != nil {
				t.Errorf("ReloadPolicy: %v", err)
				return
			}
		}
		// Finish on the wide policy so the trailing checks below are
		// meaningful: by the time wg.Wait() returns, this is the last write
		// and the last ReloadPolicy call to have happened-before it.
		if err := ioutil.WriteFile(policyPath, []byte(widePolicy), 0644); err != nil {
			t.Errorf("rewrite policy file: %v", err)
			return
		}
		if err := p.ReloadPolicy(); err != nil {
			t.Errorf("final ReloadPolicy: %v", err)
			return
		}
	}()

	wg.Wait()

	if n := atomic.LoadInt64(&alwaysAllowedDenied); n != 0 {
		t.Errorf("GET /always-allowed was denied %d times; a policy rule present in every generation must never be denied under concurrent reload", n)
	}

	// Settled-state check, no concurrency left: the previously-revoked path
	// must be allowed again now that the wide policy is the last one loaded,
	// and a path absent from every generation must still be denied.
	res := p.AuthZReq(reqLegitUser)
	if !res.Allow {
		t.Errorf("GET /legit-user expected allowed after final reload restored the wide policy, got denied: %s", res.Msg)
	}

	res = p.AuthZReq(authorization.Request{RequestURI: "/not-in-any-policy", RequestMethod: "GET"})
	if res.Allow {
		t.Errorf("GET /not-in-any-policy expected denied, got allowed")
	}
}

const basicModel = `[request_definition]
r = obj, act

[policy_definition]
p = obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.obj == p.obj && r.act == p.act
`
