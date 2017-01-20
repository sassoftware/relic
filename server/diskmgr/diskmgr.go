/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package diskmgr

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
)

type ReqId uint
type CancelFunc func()

type Manager struct {
	total        uint64
	free         uint64
	request      chan request
	release      chan ReqId
	reqIdCounter ReqId
	pending      list.List
	active       map[ReqId]*allocation

	mu     sync.Mutex
	logger *log.Logger
	debug  bool
}

// an unfulfilled request for disk space
type request struct {
	ready  chan<- error
	cancel <-chan bool
	size   uint64
	info   interface{}
	reqId  ReqId // filled by manager
}

// allocation info kept by the manager
type allocation struct {
	size uint64
	info interface{}
}

func New(size uint64) *Manager {
	m := &Manager{
		total:   size,
		free:    size,
		request: make(chan request),
		release: make(chan ReqId),
	}
	go m.Loop()
	return m
}

func (m *Manager) SetLogger(logger *log.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logger = logger
}

func (m *Manager) SetDebug(debug bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debug = debug
}

func (m *Manager) logf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.debug && m.logger != nil {
		m.logger.Output(2, fmt.Sprintf(format, args...))
	}
}

func (m *Manager) Request(ctx context.Context, size uint64, info interface{}) (CancelFunc, error) {
	ready := make(chan error)
	cancel := make(chan bool)
	cancelFunc := func() { close(cancel) }
	m.request <- request{ready, cancel, size, info, 0}
	select {
	case err := <-ready:
		if err != nil {
			return nil, err
		} else {
			return cancelFunc, nil
		}
	case <-ctx.Done():
		cancelFunc()
		return nil, ctx.Err()
	}
}

func (m *Manager) Loop() {
	m.active = make(map[ReqId]*allocation)
	for {
		select {
		case req := <-m.request:
			reqId := m.reqIdCounter
			req.reqId = reqId
			m.reqIdCounter++
			if req.size <= m.free {
				m.finishAlloc(req)
			} else if req.size <= m.total {
				// save for later
				m.pending.PushBack(&req)
				m.logf("disk: postponed %d bytes for %s", req.size, req.info)
			} else {
				// this will never work
				req.ready <- ErrTooBig
				continue
			}
			// funnel the per-request channel into a manager-wide one that Loop() can select
			go func(release chan<- ReqId, cancel <-chan bool) {
				<-cancel
				release <- reqId
			}(m.release, req.cancel)
			req.cancel = nil
		case reqId := <-m.release:
			m.releaseById(reqId)
			m.tryAlloc()
		}
	}
}

func (m *Manager) finishAlloc(req request) {
	m.free -= req.size
	m.active[req.reqId] = &allocation{req.size, req.info}
	req.ready <- nil
	m.logf("disk: allocated %d bytes for %s", req.size, req.info)
}

func (m *Manager) releaseById(reqId ReqId) {
	if alloc := m.active[reqId]; alloc != nil {
		m.logf("disk: freed %d bytes for %s", alloc.size, alloc.info)
		m.free += alloc.size
		delete(m.active, reqId)
	}
	for e := m.pending.Front(); e != nil; e = e.Next() {
		req := e.Value.(*request)
		if req.reqId == reqId {
			m.logf("disk: cancelled pending request %d bytes for %s", req.size, req.info)
			m.pending.Remove(e)
			break
		}
	}
}

func (m *Manager) tryAlloc() {
	var e, f *list.Element
	for e = m.pending.Front(); e != nil; e = f {
		f = e.Next()
		req := e.Value.(*request)
		if req.size > m.free {
			continue
		}
		m.pending.Remove(e)
		m.finishAlloc(*req)
	}
}

var ErrTooBig = errors.New("file is larger than all available disk space")
