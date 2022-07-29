package awstoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/passprompt"
	"github.com/sassoftware/relic/v7/token"
)

const tokenType = "aws"

type awsToken struct {
	config *config.Config
	tconf  *config.TokenConfig
	cli    *kms.Client
}

type awsKey struct {
	kconf *config.KeyConfig
	cli   *kms.Client
	pub   crypto.PublicKey
}

func init() {
	token.Openers[tokenType] = open
}

func open(conf *config.Config, tokenName string, pinProvider passprompt.PasswordGetter) (token.Token, error) {
	tconf, err := conf.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	cli := kms.NewFromConfig(cfg)
	return &awsToken{
		config: conf,
		tconf:  tconf,
		cli:    cli,
	}, nil
}

func (t *awsToken) Close() error {
	return nil
}

func (t *awsToken) Ping(ctx context.Context) error {
	// TODO
	return nil
}

func (t *awsToken) Config() *config.TokenConfig {
	return t.tconf
}

func (t *awsToken) GetKey(ctx context.Context, keyName string) (token.Key, error) {
	keyConf, err := t.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	if keyConf.ID == "" {
		return nil, fmt.Errorf("key %q must have \"id\" set to the ID or ARN of the key", keyName)
	}
	id := keyConf.ID
	resp, err := t.cli.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &id})
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, err
	}
	return &awsKey{
		kconf: keyConf,
		cli:   t.cli,
		pub:   pub,
	}, nil
}

func (t *awsToken) Import(keyName string, privKey crypto.PrivateKey) (token.Key, error) {
	return nil, token.NotImplementedError{Op: "import-key", Type: tokenType}
}

func (t *awsToken) ImportCertificate(cert *x509.Certificate, labelBase string) error {
	return token.NotImplementedError{Op: "import-certificate", Type: tokenType}
}

func (t *awsToken) Generate(keyName string, keyType token.KeyType, bits uint) (token.Key, error) {
	return nil, token.NotImplementedError{Op: "generate-key", Type: tokenType}
}

func (t *awsToken) ListKeys(opts token.ListOptions) error {
	return token.NotImplementedError{Op: "list-keys", Type: tokenType}
}

func (k *awsKey) Public() crypto.PublicKey {
	return k.pub
}

func (k *awsKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.SignContext(context.Background(), digest, opts)
}

func (k *awsKey) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	alg, err := k.sigAlgorithm(opts)
	if err != nil {
		return nil, err
	}
	id := k.kconf.ID
	resp, err := k.cli.Sign(ctx, &kms.SignInput{
		KeyId:            &id,
		Message:          digest,
		SigningAlgorithm: types.SigningAlgorithmSpec(alg),
		MessageType:      types.MessageTypeDigest,
	})
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

func (k *awsKey) Config() *config.KeyConfig {
	return k.kconf
}

func (k *awsKey) Certificate() []byte {
	return nil
}

func (k *awsKey) GetID() []byte {
	return nil
}

func (k *awsKey) ImportCertificate(cert *x509.Certificate) error {
	return token.NotImplementedError{Op: "import-certificate", Type: tokenType}
}

func (k *awsKey) sigAlgorithm(opts crypto.SignerOpts) (string, error) {
	var alg string
	switch opts.HashFunc() {
	case crypto.SHA256:
		alg = "SHA_256"
	case crypto.SHA384:
		alg = "SHA_384"
	case crypto.SHA512:
		alg = "SHA_512"
	default:
		return "", token.KeyUsageError{
			Key: k.kconf.Name(),
			Err: fmt.Errorf("unsupported digest algorithm %s", opts.HashFunc()),
		}
	}
	switch k.pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			return "RSASSA_PSS_" + alg, nil
		} else {
			return "RSASSA_PKCS1_V1_5_" + alg, nil
		}
	case *ecdsa.PublicKey:
		return "ECDSA_" + alg, nil
	default:
		return "", token.KeyUsageError{
			Key: k.kconf.Name(),
			Err: fmt.Errorf("unsupported public key type %T", k.pub),
		}
	}
}
