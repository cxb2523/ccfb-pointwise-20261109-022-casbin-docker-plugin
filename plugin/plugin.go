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

package plugin

import (
	"log"
	"net/url"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/docker/go-plugins-helpers/authorization"
)

// CasbinAuthZPlugin is the Casbin Authorization Plugin
type CasbinAuthZPlugin struct {
	// Casbin enforcer.
	//
	// We deliberately use casbin's SyncedEnforcer instead of the plain
	// Enforcer. The plain Enforcer has *no* internal locking: LoadPolicy()
	// clears the in-memory policy model and repopulates it from the adapter
	// in two separate, unsynchronized steps. A concurrent Enforce() call that
	// lands between those steps can observe an empty or half-rebuilt policy
	// set, which flips the verdict for every request in flight at reload
	// time (legitimate users denied, or - worse - revoked users allowed
	// because their old grant hasn't been cleared yet).
	//
	// SyncedEnforcer fixes this with a single sync.RWMutex: Enforce() takes
	// RLock (so concurrent requests still run in parallel with each other),
	// and LoadPolicy() takes the full Lock (so a reload is exclusive with
	// every in-flight Enforce()). We chose this single coarse-grained lock
	// over a finer-grained scheme (e.g. locking individual policy rows, or
	// building the new policy set off to the side and swapping a pointer)
	// for two reasons:
	//   1. Policy reloads are rare (operator-triggered or on a slow timer)
	//      compared to Enforce() calls, so a reload briefly blocking new
	//      requests is an acceptable, bounded latency hit - whereas any
	//      scheme that lets Enforce() observe a partially-written policy
	//      set is a correctness bug, not a performance trade-off.
	//      Finer-grained locking only pays off if reloads are frequent
	//      enough for the stall to matter, which is not the case here.
	//   2. A single RWMutex still lets all concurrent Enforce() calls proceed
	//      together under RLock, so request throughput is unaffected outside
	//      of the reload window. We get "correct and fast enough" without the
	//      complexity (and new bug surface) of copy-on-write policy swapping.
	enforcer *casbin.SyncedEnforcer
}

// newPlugin creates a new casbin authorization plugin
func NewPlugin(casbinModel string, casbinPolicy string) (*CasbinAuthZPlugin, error) {
	plugin := &CasbinAuthZPlugin{}

	var err error
	plugin.enforcer, err = casbin.NewSyncedEnforcer(casbinModel, casbinPolicy)

	return plugin, err
}

// ReloadPolicy hot-reloads the policy file under the enforcer's write lock,
// exclusively with any in-flight AuthZReq/Enforce call. Exposed so callers
// (e.g. a SIGHUP handler or a file watcher) can trigger a reload without
// reaching into the enforcer directly.
func (plugin *CasbinAuthZPlugin) ReloadPolicy() error {
	return plugin.enforcer.LoadPolicy()
}

// normalizeRequest turns the raw Docker request URI/method into the (obj,
// act) pair Enforce() expects, and reports whether normalization succeeded.
//
// This runs entirely before any policy-lock is taken: it does not touch the
// enforcer, so doing the work here keeps string parsing, unescaping and
// case/slash normalization out of the RLock critical section. That matters
// because this step has no need for policy data at all, and the lock should
// only guard the actual read/write of policy state.
func normalizeRequest(req authorization.Request) (obj string, act string, ok bool) {
	reqURI, err := url.QueryUnescape(req.RequestURI)
	if err != nil {
		log.Println("Failed to unescape request URI:", req.RequestURI, err)
		return "", "", false
	}

	reqURL, err := url.ParseRequestURI(reqURI)
	if err != nil || reqURL == nil {
		log.Println("Failed to parse request URI:", reqURI)
		return "", "", false
	}

	// Normalize path case and strip a single trailing slash (but keep "/"
	// itself) so that policy rules don't have to enumerate every
	// equivalent spelling of the same path. Query/fragment are preserved
	// via reqURL.String() for matchers that rely on them.
	path := strings.ToLower(reqURL.Path)
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}
	reqURL.Path = path

	act = strings.ToUpper(req.RequestMethod)
	if act == "" {
		log.Println("Missing request method for URI:", reqURI)
		return "", "", false
	}

	return reqURL.String(), act, true
}

// AuthZReq authorizes the docker client command.
// The command is allowed only if it matches a Casbin policy rule.
// Otherwise, the request is denied!
func (plugin *CasbinAuthZPlugin) AuthZReq(req authorization.Request) authorization.Response {
	// Path/method normalization happens before the enforcer is touched, so
	// none of this work is paid for while holding the policy read lock. Any
	// normalization failure denies outright - it never falls back to allow,
	// so a transient parse failure (or the race window around a policy
	// reload) can never turn into a bypass.
	obj, act, ok := normalizeRequest(req)
	if !ok {
		return authorization.Response{Allow: false, Msg: "Invalid request URI"}
	}

	// SyncedEnforcer.Enforce takes an RLock internally for the duration of
	// this call, so it always reads a complete, consistent policy snapshot
	// - never one that's been partially cleared/rebuilt by a concurrent
	// LoadPolicy.
	allowed, err := plugin.enforcer.Enforce(obj, act)
	if err != nil {
		log.Println("Enforce error:", err)
		return authorization.Response{Allow: false, Msg: "Authorization error: " + err.Error()}
	}

	if allowed {
		log.Println("obj:", obj, ", act:", act, "res: allowed")
		return authorization.Response{Allow: true}
	}

	log.Println("obj:", obj, ", act:", act, "res: denied")
	return authorization.Response{Allow: false, Msg: "Access denied by casbin plugin"}
}

// AuthZRes authorizes the docker client response.
// All responses are allowed by default.
func (plugin *CasbinAuthZPlugin) AuthZRes(req authorization.Request) authorization.Response {
	// Allowed by default.
	return authorization.Response{Allow: true}
}
