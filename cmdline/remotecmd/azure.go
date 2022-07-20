package remotecmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/gregjones/httpcache"
	"github.com/gregjones/httpcache/diskcache"
	"github.com/peterbourgon/diskv"
	"github.com/sassoftware/relic/v7/lib/dlog"
	"golang.org/x/oauth2"
)

type azureSource struct {
	cli    public.Client
	useAT  bool
	scopes []string
}

func azureTokenSource(authority, clientID string, scopes []string) (oauth2.TokenSource, error) {
	if authority == "" || clientID == "" {
		return nil, errors.New("authority and clientID are required")
	}
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	s := &azureSource{scopes: scopes}
	// The returned access token can be used if an app-specific scope was
	// requested. Otherwise it will be an in opaque format and we must use the
	// generic ID token.
	for _, scope := range scopes {
		if strings.HasPrefix(scope, "app://"+clientID) || strings.HasPrefix(scope, "https://") {
			s.useAT = true
		}
	}
	// cache both azure metadata and the resulting tokens
	cacheBase, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	cacheBase = filepath.Join(cacheBase, "relic")
	storage := diskv.New(diskv.Options{
		BasePath:     cacheBase,
		TempDir:      filepath.Join(cacheBase, "tmp"),
		CacheSizeMax: 10e6,
	})
	// build HTTP transport with a cache
	tr := loggingTransport{RoundTripper: http.DefaultTransport}
	cache := httpcache.NewTransport(diskcache.NewWithDiskv(storage))
	cache.Transport = tr
	hc := &http.Client{Transport: cache}
	// configure MSAL
	s.cli, err = public.New(clientID,
		public.WithAuthority(authority),
		public.WithCache(&dvCache{
			dv:  storage,
			key: "msal-" + clientID,
		}),
		public.WithHTTPClient(hc),
	)
	if err != nil {
		return nil, err
	}
	return oauth2.ReuseTokenSource(nil, s), nil
}

func (s *azureSource) Token() (*oauth2.Token, error) {
	// use cached token or silently refresh
	if acc := s.cli.Accounts(); len(acc) != 0 {
		result, err := s.cli.AcquireTokenSilent(context.Background(), s.scopes, public.WithSilentAccount(acc[0]))
		if err != nil {
			log.Println("warning: failed to refresh cached token:", err)
		} else {
			return s.toToken(result)
		}
	}
	// use browser to interactively authenticate
	fmt.Fprintln(os.Stderr, "attempting interactive login")
	result, err := s.cli.AcquireTokenInteractive(context.Background(), s.scopes)
	if err == nil {
		return s.toToken(result)
	} else if !errors.As(err, new(*exec.ExitError)) && !errors.As(err, new(*exec.Error)) {
		return nil, err
	}
	// use device code
	fmt.Fprintln(os.Stderr, "attempting device code login")
	dc, err := s.cli.AcquireTokenByDeviceCode(context.Background(), s.scopes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dc.Result.Message)
	fmt.Fprintln(os.Stderr)
	result, err = dc.AuthenticationResult(context.Background())
	if err != nil {
		return nil, err
	}
	return s.toToken(result)
}

func (s *azureSource) toToken(res public.AuthResult) (*oauth2.Token, error) {
	if s.useAT {
		return &oauth2.Token{
			AccessToken: res.AccessToken,
			Expiry:      res.ExpiresOn,
		}, nil
	}
	return &oauth2.Token{
		AccessToken: res.IDToken.RawToken,
		Expiry:      time.Unix(res.IDToken.ExpirationTime, 0),
	}, nil
}

// dvCache adapts the diskv key-value store to act as MSAL's persistence layer
type dvCache struct {
	dv  *diskv.Diskv
	key string
}

func (c *dvCache) Export(cache cache.Marshaler, key string) {
	data, err := cache.Marshal()
	if err == nil {
		err = c.dv.Write(c.key, data)
	}
	if err != nil {
		log.Println("error: persisting access token:", err)
	}
}

func (c *dvCache) Replace(cache cache.Unmarshaler, key string) {
	data, err := c.dv.Read(c.key)
	if err == nil {
		err = cache.Unmarshal(data)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Println("error: reading cached access token:", err)
	}
}

type loggingTransport struct {
	RoundTripper http.RoundTripper
}

func (t loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	dlog.Printf(3, "auth > %s %s", req.Method, req.URL)
	resp, err := t.RoundTripper.RoundTrip(req)
	if err != nil {
		dlog.Printf(3, "auth < %+v", err)
	} else {
		dlog.Printf(3, "auth < %s", resp.Status)
	}
	return resp, err
}
