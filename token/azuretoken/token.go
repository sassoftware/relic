package azuretoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/go-jose/go-jose/v3"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/passprompt"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/token"
)

const tokenType = "azure"

type kvToken struct {
	config *config.Config
	tconf  *config.TokenConfig
	cli    *keyvault.BaseClient
}

type kvKey struct {
	kconf    *config.KeyConfig
	cli      *keyvault.BaseClient
	pub      crypto.PublicKey
	kbase    string
	kname    string
	kversion string
	id       []byte
	cert     []byte
}

func init() {
	token.Openers[tokenType] = open
}

func open(conf *config.Config, tokenName string, pinProvider passprompt.PasswordGetter) (token.Token, error) {
	tconf, err := conf.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	auth, err := newAuthorizer(tconf)
	if err != nil {
		return nil, fmt.Errorf("configuring azure auth: %w", err)
	}
	cli := keyvault.New()
	cli.Authorizer = auth
	return &kvToken{
		config: conf,
		tconf:  tconf,
		cli:    &cli,
	}, nil
}

func (t *kvToken) Close() error {
	return nil
}

func (t *kvToken) Ping(ctx context.Context) error {
	// query info for one of the keys in this token
	for _, keyConf := range t.config.Keys {
		if keyConf.Token != t.tconf.Name() || keyConf.Hide {
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, keyConf.GetTimeout())
		defer cancel()
		_, err := t.getKey(ctx, keyConf, true)
		if err != nil {
			return fmt.Errorf("checking key %q: %w", keyConf.Name(), err)
		}
		break
	}
	return nil
}

func (t *kvToken) Config() *config.TokenConfig {
	return t.tconf
}

func (t *kvToken) GetKey(ctx context.Context, keyName string) (token.Key, error) {
	keyConf, err := t.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	return t.getKey(ctx, keyConf, false)
}

func (t *kvToken) getKey(ctx context.Context, keyConf *config.KeyConfig, pingOnly bool) (token.Key, error) {
	words, baseURL, err := parseKeyURL(keyConf.ID)
	if err != nil {
		return nil, fmt.Errorf("key %q: %w", keyConf.Name(), err)
	}
	wantKeyID := token.KeyID(ctx)
	var cert *certRef
	switch {
	case len(wantKeyID) != 0:
		// reusing a key the client saw before
		cert = refFromKeyID(wantKeyID)
		if cert == nil {
			return nil, errors.New("invalid keyID")
		}
		cert = &certRef{KeyName: words[0], KeyVersion: words[1]}
	case len(words) == 4 && words[1] == "keys":
		// directly to a key version, no cert provided
		cert = &certRef{KeyName: words[2], KeyVersion: words[3]}
	case len(words) == 4 && words[1] == "certificates":
		// link to a cert version, get the key version and cert contents from it
		cert, err = t.loadCertificateVersion(ctx, baseURL, words[2], words[3])
		if err != nil {
			return nil, fmt.Errorf("key %q: fetching certificate: %w", keyConf.Name(), err)
		} else if pingOnly {
			return nil, nil
		}
	case len(words) == 3 && words[1] == "certificates":
		// link to a cert, pick the latest version
		cert, err = t.loadCertificateLatest(ctx, baseURL, words[2])
		if err != nil {
			return nil, fmt.Errorf("key %q: fetching certificate: %w", keyConf.Name(), err)
		} else if pingOnly {
			return nil, nil
		}
	default:
		return nil, fmt.Errorf("key %q: %w", keyConf.Name(), errKeyID)
	}
	key, err := t.cli.GetKey(ctx, baseURL, cert.KeyName, cert.KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("key %q: %w", keyConf.Name(), err)
	} else if pingOnly {
		return nil, nil
	}
	// strip off -HSM suffix to get a key type jose will accept
	kty := strings.TrimSuffix(string(key.Key.Kty), "-HSM")
	key.Key.Kty = keyvault.JSONWebKeyType(kty)
	// marshal back to JSON and then parse using jose to get a PublicKey
	keyBlob, err := json.Marshal(key.Key)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(keyBlob, &jwk); err != nil {
		return nil, fmt.Errorf("unmarshaling public key: %w", err)
	}
	return &kvKey{
		kconf:    keyConf,
		cli:      t.cli,
		pub:      jwk.Key,
		kbase:    baseURL,
		kname:    cert.KeyName,
		kversion: cert.KeyVersion,
		cert:     cert.CertBlob,
		id:       cert.KeyID(),
	}, nil
}

func (t *kvToken) Import(keyName string, privKey crypto.PrivateKey) (token.Key, error) {
	return nil, token.NotImplementedError{Op: "import-key", Type: tokenType}
}

func (t *kvToken) ImportCertificate(cert *x509.Certificate, labelBase string) error {
	return token.NotImplementedError{Op: "import-certificate", Type: tokenType}
}

func (t *kvToken) Generate(keyName string, keyType token.KeyType, bits uint) (token.Key, error) {
	return nil, token.NotImplementedError{Op: "generate-key", Type: tokenType}
}

func (t *kvToken) ListKeys(opts token.ListOptions) error {
	return token.NotImplementedError{Op: "list-keys", Type: tokenType}
}

func (k *kvKey) Public() crypto.PublicKey {
	return k.pub
}

func (k *kvKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.SignContext(context.Background(), digest, opts)
}

func (k *kvKey) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	alg, err := k.sigAlgorithm(opts)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(digest)
	kname, kversion := k.kname, k.kversion
	if wantKeyID := token.KeyID(ctx); len(wantKeyID) != 0 {
		// reusing a key the client saw before
		cert := refFromKeyID(wantKeyID)
		if cert == nil {
			return nil, errors.New("invalid keyID")
		}
		kname, kversion = cert.KeyName, cert.KeyVersion
	}
	resp, err := k.cli.Sign(ctx, k.kbase, kname, kversion, keyvault.KeySignParameters{
		Algorithm: keyvault.JSONWebKeySignatureAlgorithm(alg),
		Value:     &encoded,
	})
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(*resp.Result)
	if err != nil {
		return nil, err
	}
	if _, ok := k.pub.(*ecdsa.PublicKey); ok {
		// repack as ASN.1
		unpacked, err := x509tools.UnpackEcdsaSignature(sig)
		if err != nil {
			return nil, err
		}
		sig = unpacked.Marshal()
	}
	return sig, nil
}

func (k *kvKey) Config() *config.KeyConfig { return k.kconf }
func (k *kvKey) Certificate() []byte       { return k.cert }
func (k *kvKey) GetID() []byte             { return k.id }

func (k *kvKey) ImportCertificate(cert *x509.Certificate) error {
	return token.NotImplementedError{Op: "import-certificate", Type: tokenType}
}

// select a JOSE signature algorithm based on the public key algorithm and requested hash func
func (k *kvKey) sigAlgorithm(opts crypto.SignerOpts) (string, error) {
	var alg string
	switch opts.HashFunc() {
	case crypto.SHA256:
		alg = "256"
	case crypto.SHA384:
		alg = "384"
	case crypto.SHA512:
		alg = "512"
	default:
		return "", token.KeyUsageError{
			Key: k.kconf.Name(),
			Err: fmt.Errorf("unsupported digest algorithm %s", opts.HashFunc()),
		}
	}
	switch k.pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			return "PS" + alg, nil
		} else {
			return "RS" + alg, nil
		}
	case *ecdsa.PublicKey:
		return "ES" + alg, nil
	default:
		return "", token.KeyUsageError{
			Key: k.kconf.Name(),
			Err: fmt.Errorf("unsupported public key type %T", k.pub),
		}
	}
}
