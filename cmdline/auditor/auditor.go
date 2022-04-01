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

package auditor

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/streadway/amqp"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/activation"
	"github.com/sassoftware/relic/v7/lib/audit"

	_ "github.com/lib/pq"
)

var AuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Receive audit data from relic servers",
	RunE:  auditCmd,
}

var argConfigFile string

func init() {
	shared.RootCmd.AddCommand(AuditCmd)
	AuditCmd.Flags().StringVarP(&argConfigFile, "config", "c", "", "Name of relic-audit configuration file")
}

func auditCmd(cmd *cobra.Command, args []string) error {
	if err := readConfig(); err != nil {
		return err
	}
	configs, err := getServerConfs()
	if err != nil {
		return err
	}
	// test logfile but open it as-needed to make rotation simpler
	if auditConfig.LogFile != "" {
		f, err := os.OpenFile(auditConfig.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return err
		}
		f.Close()
	}
	// open and test database connection. the sql module manages a pool for goroutines as needed.
	db, err := openDb()
	if err != nil {
		return err
	}
	if err := db.Ping(); err != nil {
		return err
	}
	// start listeners for each broker
	for _, cfg := range configs {
		if err := startListener(cfg, db); err != nil {
			return fmt.Errorf("%s: %w", cfg.Path(), err)
		}
	}
	_ = activation.DaemonReady()
	// nothing left to do in this goroutine
	time.Sleep(1<<63 - 1)
	return nil
}

func openDb() (*sql.DB, error) {
	return sql.Open("postgres", auditConfig.DatabaseURI)
}

func startListener(conf *config.Config, db *sql.DB) error {
	aconf := conf.Amqp
	l, err := NewListener(aconf)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: connected\n", conf.Path())
	go func() {
		l2 := l
		var start time.Time
		delay := new(expBackoff)
		for {
			if l2 != nil {
				if err := l2.Loop(db); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s\n", conf.Path(), err)
				}
				l2.Close()
				l2 = nil
			}
			delay.CancelReset()
			if time.Since(start) < time.Second {
				delay.Sleep()
			}
			var err error
			start = time.Now()
			l2, err = NewListener(aconf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %s\n", conf.Path(), err)
			} else {
				fmt.Fprintf(os.Stderr, "%s: connection reestablished\n", conf.Path())
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
	if err := ch.ExchangeDeclarePassive(aconf.ExchangeName(), amqp.ExchangeFanout, true, false, false, false, nil); err != nil {
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

func (l *Listener) Loop(db *sql.DB) error {
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
			if err := d.Ack(false); err != nil {
				return err
			}
			continue
		}
		if err := logToAll(db, info); err != nil {
			// reject the message, disconnect, and start a timeout
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
			_ = d.Reject(true)
			return err
		}
		if err := d.Ack(false); err != nil {
			return err
		}
	}
	if err := <-errch; err != nil {
		return err
	}
	return nil
}

func logToAll(db *sql.DB, info *audit.Info) (err error) {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:Errcheck
	rowid, err := insertRow(db, info)
	if err != nil {
		return err
	}
	if err := logGraylog(info, rowid); err != nil {
		return err
	}
	if err := logToFile(info, rowid); err != nil {
		return err
	}
	return tx.Commit()
}

func insertRow(db *sql.DB, info *audit.Info) (int64, error) {
	blob, err := info.Marshal()
	if err != nil {
		return 0, err
	}
	attrs64 := base64.StdEncoding.EncodeToString(blob)
	var rowid int64
	row := db.QueryRow("INSERT INTO signatures (timestamp, client_name, client_ip, client_dn, client_filename, sig_hostname, sig_type, sig_keyname, attributes) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING signature_id",
		info.Attributes["sig.timestamp"],
		info.Attributes["client.name"],
		info.Attributes["client.ip"],
		info.Attributes["client.dn"],
		info.Attributes["client.filename"],
		info.Attributes["sig.hostname"],
		info.Attributes["sig.type"],
		info.Attributes["sig.keyname"],
		attrs64,
	)
	if err := row.Scan(&rowid); err != nil {
		return 0, err
	}
	return rowid, nil
}

func logToFile(info *audit.Info, rowid int64) error {
	formatted := fmtRow(info, rowid)
	if auditConfig.LogFile != "" {
		f, err := os.OpenFile(auditConfig.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := fmt.Fprintln(f, formatted); err != nil {
			return err
		}
	} else {
		fmt.Println(formatted)
	}
	return nil
}

func fmtRow(info *audit.Info, rowid int64) string {
	client := info.Attributes["client.name"]
	if client == nil {
		client = ""
	}
	ip := info.Attributes["client.ip"]
	if ip == nil {
		ip = ""
	}
	dn := info.Attributes["client.dn"]
	if dn == nil {
		dn = ""
	}
	return fmt.Sprintf("[%s] client=%s dn=%s ip=%s server=%s sigtype=%s filename=%s key=%s rowid=%d",
		info.Attributes["sig.timestamp"],
		client,
		dn,
		ip,
		info.Attributes["sig.hostname"],
		info.Attributes["sig.type"],
		info.Attributes["client.filename"],
		info.Attributes["sig.keyname"],
		rowid,
	)
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
