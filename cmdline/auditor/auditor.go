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

package auditor

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/audit"
	"gerrit-pdt.unx.sas.com/tools/relic.git/server/activation"
	"github.com/spf13/cobra"
	"github.com/streadway/amqp"
)

var AuditCmd = &cobra.Command{
	Short: "Receive audit data from relic servers",
	RunE:  auditCmd,
}

var argConfigsDir string

func init() {
	AuditCmd.Flags().StringVarP(&argConfigsDir, "configs-dir", "d", "", "Directory of audit config files to load")
}

func auditCmd(cmd *cobra.Command, args []string) error {
	if argConfigsDir != "" {
		dir, err := os.Open(argConfigsDir)
		if err != nil {
			return err
		}
		defer dir.Close()
		names, err := dir.Readdirnames(-1)
		if err != nil {
			return err
		}
		sort.Strings(names)
		for _, name := range names {
			args = append(args, path.Join(argConfigsDir, name))
		}
	} else if len(args) == 0 {
		return errors.New("provide one or more config files as arguments, or pass --configs-dir")
	}
	for _, path := range args {
		cfg, err := config.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %s", path, err)
		}
		if cfg.Amqp == nil || cfg.Amqp.Url == "" {
			return fmt.Errorf("%s has no amqp server", path)
		}
		if err := startListener(path, cfg.Amqp); err != nil {
			return fmt.Errorf("%s: %s", path, err)
		}
	}
	activation.DaemonReady()
	time.Sleep(1<<63 - 1)
	return nil
}

func startListener(path string, aconf *config.AmqpConfig) error {
	l, err := NewListener(aconf)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: connected\n", path)
	go func() {
		l2 := l
		var start time.Time
		delay := new(expBackoff)
		for {
			if l2 != nil {
				if err := l2.Loop(); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
				}
				l2.Close()
				l2 = nil
			}
			delay.CancelReset()
			if time.Now().Sub(start) < time.Second {
				delay.Sleep()
			}
			var err error
			start = time.Now()
			l2, err = NewListener(aconf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
			} else {
				fmt.Fprintf(os.Stderr, "%s: connection reestablished\n", path)
				delay.ResetAfter(60 * time.Second)
			}
		}
	}()
	return nil
}

type Listener struct {
	aconf *config.AmqpConfig
	conn  *amqp.Connection
	ch    *amqp.Channel
	qname string
}

func NewListener(aconf *config.AmqpConfig) (*Listener, error) {
	conn, err := audit.Connect(aconf)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	qname := "audit." + hostname
	l := &Listener{aconf, conn, ch, qname}
	if err := ch.ExchangeDeclare(aconf.ExchangeName(), amqp.ExchangeFanout, true, false, false, false, nil); err != nil {
		l.Close()
		return nil, err
	}
	if _, err := ch.QueueDeclare(qname, true, false, false, false, nil); err != nil {
		l.Close()
		return nil, err
	}
	if err := ch.QueueBind(qname, "", aconf.ExchangeName(), false, nil); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (l *Listener) Loop() error {
	errch := l.conn.NotifyClose(make(chan *amqp.Error, 1))
	delivery, err := l.ch.Consume(l.qname, "", false, true, false, false, nil)
	if err != nil {
		return err
	}
	for {
		d, ok := <-delivery
		if !ok {
			break
		}
		info, err := audit.Parse(d.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse failed: %s\n", err)
			d.Ack(false)
			continue
		}
		fmt.Printf("[%s] client=%s ip=%s server=%s sigtype=%s filename=%s key=%s\n",
			info.Attributes["sig.timestamp"],
			info.Attributes["client.name"],
			info.Attributes["client.ip"],
			info.Attributes["sig.hostname"],
			info.Attributes["sig.type"],
			info.Attributes["client.filename"],
			info.Attributes["sig.keyname"],
		)
		d.Ack(false)
	}
	return <-errch
}

func (l *Listener) Close() error {
	if l.ch != nil {
		l.ch.Close()
		l.ch = nil
	}
	if l.conn != nil {
		l.conn.Close()
		l.conn = nil
	}
	return nil
}

const (
	backoffMin = 1
	backoffMax = 60
	backoffE   = 2.7182818284590451
)

type expBackoff struct {
	e float32
	t *time.Timer
}

func (e *expBackoff) Sleep() {
	if e.e == 0 {
		e.e = backoffMin
	}
	time.Sleep(time.Duration(e.e * float32(time.Second)))
	e.e *= backoffE
	if e.e > backoffMax {
		e.e = backoffMax
	}
}

func (e *expBackoff) ResetAfter(d time.Duration) {
	if e.t != nil {
		e.t.Stop()
	}
	e.t = time.AfterFunc(d, func() {
		e.e = 0
	})
}

func (e *expBackoff) CancelReset() {
	if e.t != nil {
		e.t.Stop()
		e.t = nil
	}
}
