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

package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/token"
)

var NewPgpKeyCmd = &cobra.Command{
	Use:   "pgp-generate",
	Short: "Generate a new PGP key from token",
	RunE:  newPgpKeyCmd,
}

var (
	argUserName    string
	argUserComment string
	argUserEmail   string
)

func init() {
	shared.RootCmd.AddCommand(NewPgpKeyCmd)
	NewPgpKeyCmd.Flags().StringVarP(&argUserName, "name", "n", "", "Name of user identity")
	NewPgpKeyCmd.Flags().StringVarP(&argUserComment, "comment", "C", "", "Comment of user identity")
	NewPgpKeyCmd.Flags().StringVarP(&argUserEmail, "email", "E", "", "Email of user identity")
	addSelectOrGenerateFlags(NewPgpKeyCmd)
}

func makeKey(key token.Key, uids []*packet.UserId) (*openpgp.Entity, error) {
	creationTime := time.Now()
	var pubKey *packet.PublicKey
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		pubKey = packet.NewRSAPublicKey(creationTime, pub)
	case *ecdsa.PublicKey:
		pubKey = packet.NewECDSAPublicKey(creationTime, pub)
	default:
		return nil, errors.New("Unsupported key type")
	}
	entity := &openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: &packet.PrivateKey{
			PublicKey:  *pubKey,
			Encrypted:  false,
			PrivateKey: key,
		},
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryID := true
	for _, uid := range uids {
		sig := &packet.Signature{
			SigType:      packet.SigTypePositiveCert,
			CreationTime: creationTime,
			PubKeyAlgo:   pubKey.PubKeyAlgo,
			Hash:         crypto.SHA512,
			IsPrimaryId:  &isPrimaryID,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &pubKey.KeyId,
		}
		err := sig.SignUserId(uid.Id, entity.PrimaryKey, entity.PrivateKey, nil)
		if err != nil {
			return nil, err
		}
		entity.Identities[uid.Id] = &openpgp.Identity{
			Name:          uid.Name,
			UserId:        uid,
			SelfSignature: sig,
		}
	}
	return entity, nil
}

func newPgpKeyCmd(cmd *cobra.Command, args []string) error {
	if argUserName == "" {
		return errors.New("--name is required")
	}
	uid := packet.NewUserId(argUserName, argUserComment, argUserEmail)
	if uid == nil {
		return errors.New("Invalid user ID")
	}
	key, err := selectOrGenerate()
	if err != nil {
		return err
	}
	entity, err := makeKey(key, []*packet.UserId{uid})
	if err != nil {
		return err
	}
	fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint[:])
	fmt.Fprintln(os.Stderr, "Token CKA_ID: ", formatKeyID(key.GetID()))
	fmt.Fprintln(os.Stderr, "PGP ID:       ", strings.ToUpper(fingerprint))
	writer, err := armor.Encode(os.Stdout, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	err = entity.Serialize(writer)
	if err != nil {
		return err
	}
	writer.Close()
	fmt.Println()
	return nil
}
