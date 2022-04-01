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

package audit

import (
	"crypto/tls"
	"errors"
	"time"

	"github.com/streadway/amqp"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

// Publish audit record to a AMQP exchange
func (info *Info) Publish(aconf *config.AmqpConfig) error {
	blob, err := info.Marshal()
	if err != nil {
		return err
	}
	msg := amqp.Publishing{
		DeliveryMode: amqp.Persistent,
		Timestamp:    time.Now(),
		ContentType:  "application/json",
		Body:         blob,
	}
	conn, err := Connect(aconf)
	if err != nil {
		return err
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()
	if err := ch.ExchangeDeclare(aconf.ExchangeName(), amqp.ExchangeFanout, true, false, false, false, nil); err != nil {
		return err
	}
	if err := ch.Confirm(false); err != nil {
		return err
	}
	notify := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
	if err := ch.Publish(aconf.ExchangeName(), aconf.RoutingKey(), false, false, msg); err != nil {
		return err
	}
	confirm := <-notify
	if !confirm.Ack {
		return errors.New("message was NACKed")
	}
	return nil
}

// Connect to the configured AMQP broker
func Connect(aconf *config.AmqpConfig) (*amqp.Connection, error) {
	uri, err := amqp.ParseURI(aconf.URL)
	if err != nil {
		return nil, err
	}
	var tconf *tls.Config
	var auth []amqp.Authentication
	if uri.Scheme == "amqps" {
		tconf = &tls.Config{}
		if aconf.CaCert != "" {
			if err := x509tools.LoadCertPool(aconf.CaCert, tconf); err != nil {
				return nil, err
			}
		}
		if aconf.CertFile != "" {
			cert, err := certloader.LoadX509KeyPair(aconf.CertFile, aconf.KeyFile)
			if err != nil {
				return nil, err
			}
			tconf.Certificates = []tls.Certificate{cert.TLS()}
		}
		x509tools.SetKeyLogFile(tconf)
		if len(tconf.Certificates) != 0 {
			auth = append(auth, externalAuth{})
		}
	}
	if uri.Password != "" {
		auth = append(auth, uri.PlainAuth())
	}
	qconf := amqp.Config{SASL: auth, TLSClientConfig: tconf}
	return amqp.DialConfig(aconf.URL, qconf)
}

type externalAuth struct{}

func (externalAuth) Mechanism() string { return "EXTERNAL" }
func (externalAuth) Response() string  { return "" }
