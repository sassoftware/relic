//
// Copyright (c) SAS Institute Inc.
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
//

package workercmd

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/internal/activation"
	"github.com/sassoftware/relic/internal/workerrpc"
	"github.com/sassoftware/relic/token"
	"github.com/sassoftware/relic/token/open"
	"github.com/spf13/cobra"
)

func init() {
	AddWorkerCommand(shared.RootCmd)
}

func AddWorkerCommand(parent *cobra.Command) {
	wc := &cobra.Command{
		Use:    "worker",
		Run:    worker,
		Hidden: true,
	}
	parent.AddCommand(wc)
}

func worker(cmd *cobra.Command, args []string) {
	log.SetFlags(0)
	if len(args) != 2 {
		log.Fatalln("invalid argument")
	}
	shared.ArgConfig = args[0]
	tokenName := args[1]
	if err := runWorker(tokenName); err != nil {
		log.Fatalf("error: worker for token \"%s\": %+v", tokenName, err)
	}
}

func runWorker(tokenName string) error {
	if err := shared.InitConfig(); err != nil {
		return err
	}
	cookie, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	lis, err := activation.GetListener(0, "tcp", "")
	if err != nil {
		return err
	}
	tok, err := open.Token(shared.CurrentConfig, tokenName, nil)
	if err != nil {
		return err
	}
	handler := &handler{
		token:  tok,
		cookie: cookie,
	}
	srv := &http.Server{Handler: handler}
	activation.DaemonReady()
	wg := new(sync.WaitGroup)
	go watchSignals(srv, wg)
	err = srv.Serve(lis)
	if err == http.ErrServerClosed {
		err = nil
	}
	wg.Wait()
	return err
}

func watchSignals(srv *http.Server, wg *sync.WaitGroup) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	<-ch
	wg.Add(1)
	go func() {
		srv.Shutdown(context.Background())
		wg.Done()
	}()
}

type handler struct {
	token    token.Token
	cookie   []byte
	keyCache sync.Map
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookie := req.Header.Get("Auth-Cookie")
	if !hmac.Equal([]byte(cookie), []byte(h.cookie)) {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	resp, err := h.handle(rw, req)
	if err != nil {
		resp.Err = err.Error()
	}
	blob, err := json.Marshal(resp)
	if err != nil {
		log.Printf("error: worker for token \"%s\": %s", h.token.Config().Name(), err)
		return
	}
	rw.Write(blob)
}

func (h *handler) handle(rw http.ResponseWriter, req *http.Request) (resp workerrpc.Response, err error) {
	blob, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return resp, err
	}
	var rr workerrpc.Request
	if err := json.Unmarshal(blob, &rr); err != nil {
		return resp, err
	}
	switch req.URL.Path {
	case workerrpc.Ping:
		return resp, h.token.Ping()
	case workerrpc.GetKey:
		key, err := h.getKey(rr.KeyName)
		if err != nil {
			return resp, err
		}
		resp.ID = key.GetID()
		resp.Value, err = x509.MarshalPKIXPublicKey(key.Public())
		return resp, err
	case workerrpc.Sign:
		hash := crypto.Hash(rr.Hash)
		opts := crypto.SignerOpts(hash)
		if rr.SaltLength != nil {
			opts = &rsa.PSSOptions{SaltLength: *rr.SaltLength, Hash: hash}
		}
		key, err := h.getKey(rr.KeyName)
		if err != nil {
			return resp, err
		}
		resp.Value, err = key.Sign(rand.Reader, rr.Digest, opts)
		return resp, err
	default:
		return resp, errors.New("invalid method: " + req.URL.Path)
	}
}

func (h *handler) getKey(keyName string) (token.Key, error) {
	key, _ := h.keyCache.Load(keyName)
	if key == nil {
		var err error
		key, err = h.token.GetKey(keyName)
		if err != nil {
			return nil, err
		}
		h.keyCache.Store(keyName, key)
	}
	return key.(token.Key), nil
}
