package gcloudtoken

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/passprompt"
	"github.com/sassoftware/relic/v7/token"
)

const tokenType = "gcloud"

type gcloudToken struct {
	config *config.Config
	tconf  *config.TokenConfig
	cli    *kms.KeyManagementClient
}

type gcloudKey struct {
	kconf *config.KeyConfig
	cli   *kms.KeyManagementClient
	pub   crypto.PublicKey
	hash  crypto.Hash
	pss   bool
}

func init() {
	token.Openers[tokenType] = open
}

func open(conf *config.Config, tokenName string, pinProvider passprompt.PasswordGetter) (token.Token, error) {
	tconf, err := conf.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var opts []option.ClientOption
	if tconf.Pin != nil {
		opts = append(opts, option.WithCredentialsFile(*tconf.Pin))
	}
	cli, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &gcloudToken{
		config: conf,
		tconf:  tconf,
		cli:    cli,
	}, nil
}

func (t *gcloudToken) Close() error {
	return t.cli.Close()
}

func (t *gcloudToken) Ping(ctx context.Context) error {
	// TODO
	return nil
}

func (t *gcloudToken) Config() *config.TokenConfig {
	return t.tconf
}

func (t *gcloudToken) GetKey(ctx context.Context, keyName string) (token.Key, error) {
	keyConf, err := t.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	if keyConf.ID == "" {
		return nil, fmt.Errorf("key %q must have \"id\" set to the fully-quaified resource name of a Cloud KMS key version", keyName)
	}
	resp, err := t.cli.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyConf.ID})
	if err != nil {
		return nil, err
	}
	hashFunc, pss := pubKeyAlgorithm(resp)
	if hashFunc == 0 {
		return nil, fmt.Errorf("key %q: unsupported type %q", keyName, resp.Algorithm.String())
	}
	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return nil, errors.New("expected PEM in public key response")
	} else if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected PUBLIC KEY in response but got %q", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &gcloudKey{
		kconf: keyConf,
		cli:   t.cli,
		pub:   pub,
		hash:  hashFunc,
		pss:   pss,
	}, nil
}

func (t *gcloudToken) Import(keyName string, privKey crypto.PrivateKey) (token.Key, error) {
	return nil, token.NotImplementedError{Op: "import-key", Type: tokenType}
}

func (t *gcloudToken) ImportCertificate(cert *x509.Certificate, labelBase string) error {
	return token.NotImplementedError{Op: "import-certificate", Type: tokenType}
}

func (t *gcloudToken) Generate(keyName string, keyType token.KeyType, bits uint) (token.Key, error) {
	return nil, token.NotImplementedError{Op: "generate-key", Type: tokenType}
}

func (t *gcloudToken) ListKeys(opts token.ListOptions) error {
	return token.NotImplementedError{Op: "list-keys", Type: tokenType}
}

func (k *gcloudKey) Public() crypto.PublicKey {
	return k.pub
}

func (k *gcloudKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.SignContext(context.Background(), digest, opts)
}

func (k *gcloudKey) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != k.hash {
		return nil, token.KeyUsageError{
			Key: k.kconf.Name(),
			Err: fmt.Errorf("tried to use digest %s but key requires digest %s", opts.HashFunc(), k.hash),
		}
	}
	if _, ok := opts.(*rsa.PSSOptions); ok && !k.pss {
		return nil, token.KeyUsageError{
			Key: k.kconf.Name(),
			Err: errors.New("tried to use RSA-PSS signature but key uses PKCS#1"),
		}
	} else if k.pss && !ok {
		return nil, token.KeyUsageError{
			Key: k.kconf.Name(),
			Err: errors.New("tried to use PKCS#1 signature but key uses RSA-PSS"),
		}
	}
	req := &kmspb.AsymmetricSignRequest{
		Name:   k.kconf.ID,
		Digest: &kmspb.Digest{},
	}
	switch k.hash {
	case crypto.SHA256:
		req.Digest.Digest = &kmspb.Digest_Sha256{Sha256: digest}
	case crypto.SHA384:
		req.Digest.Digest = &kmspb.Digest_Sha384{Sha384: digest}
	case crypto.SHA512:
		req.Digest.Digest = &kmspb.Digest_Sha512{Sha512: digest}
	default:
		return nil, token.KeyUsageError{
			Key: k.kconf.Name(),
			Err: fmt.Errorf("unsupported digest algorithm %s", k.hash),
		}
	}
	resp, err := k.cli.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

func (k *gcloudKey) Config() *config.KeyConfig {
	return k.kconf
}

func (k *gcloudKey) Certificate() []byte {
	return nil
}

func (k *gcloudKey) GetID() []byte {
	return nil
}

func (k *gcloudKey) ImportCertificate(cert *x509.Certificate) error {
	return token.NotImplementedError{Op: "import-certificate", Type: tokenType}
}

func pubKeyAlgorithm(pub *kmspb.PublicKey) (h crypto.Hash, pss bool) {
	switch pub.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256:
		return crypto.SHA256, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256:
		return crypto.SHA256, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:
		return crypto.SHA256, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return crypto.SHA512, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		return crypto.SHA256, false
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256:
		return crypto.SHA256, false
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		return crypto.SHA256, false
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return crypto.SHA512, false
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return crypto.SHA256, false
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return crypto.SHA384, false
	}
	return 0, false
}
