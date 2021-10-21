package azuretoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/go-autorest/autorest"
	"gopkg.in/square/go-jose.v2"

	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/lib/passprompt"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sassoftware/relic/token"
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
}

func init() {
	token.Openers[tokenType] = open
}

func open(conf *config.Config, tokenName string, pinProvider passprompt.PasswordGetter) (token.Token, error) {
	tconf, err := conf.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	var auth autorest.Authorizer
	if tconf.Pin != nil {
		credFile := *tconf.Pin
		if credFile == "" {
			auth, err = kvauth.NewAuthorizerFromCLI()
		} else {
			os.Setenv("AZURE_AUTH_LOCATION", credFile)
			auth, err = kvauth.NewAuthorizerFromFile()
		}
	} else {
		auth, err = kvauth.NewAuthorizerFromEnvironment()
	}
	if err != nil {
		return nil, err
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

func (t *kvToken) Ping() error {
	// TODO
	return nil
}

func (t *kvToken) Config() *config.TokenConfig {
	return t.tconf
}

func (t *kvToken) GetKey(keyName string) (token.Key, error) {
	return t.GetKeyContext(context.Background(), keyName)
}

func (t *kvToken) GetKeyContext(ctx context.Context, keyName string) (token.Key, error) {
	keyConf, err := t.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	if keyConf.ID == "" {
		return nil, fmt.Errorf("key %q must have \"id\" set to the fully-quaified key identifier URL of an Azure key version", keyName)
	}
	// deconstruct URL to call GetKey so it can put it back together again
	u, err := url.Parse(keyConf.ID)
	if err != nil {
		return nil, fmt.Errorf("key %q: id: %w", keyName, err)
	} else if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("key %q: id: invalid URL", keyName)
	}
	words := strings.Split(u.Path, "/")
	if len(words) != 4 || words[1] != "keys" {
		return nil, fmt.Errorf("key %q: id: expected https://{vaultname}.vault.azure.net/keys/{keyname}/{keyversion}", keyName)
	}
	kname, kversion := words[2], words[3]
	u.Path = ""
	baseURL := u.String()
	key, err := t.cli.GetKey(ctx, baseURL, kname, kversion)
	if err != nil {
		return nil, err
	}
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
		kname:    kname,
		kversion: kversion,
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
	resp, err := k.cli.Sign(ctx, k.kbase, k.kname, k.kversion, keyvault.KeySignParameters{
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

func (k *kvKey) Config() *config.KeyConfig {
	return k.kconf
}

func (k *kvKey) GetID() []byte {
	return nil
}

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
