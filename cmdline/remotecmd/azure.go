package remotecmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/cli/browser"
	"github.com/gregjones/httpcache"
	"github.com/gregjones/httpcache/diskcache"
	"github.com/peterbourgon/diskv"
	"github.com/sassoftware/relic/v7/lib/dlog"
	"golang.org/x/oauth2"
)

type azureSource struct {
	cli    public.Client
	dvc    *dvCache
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
	s.dvc = &dvCache{
		dv:  storage,
		key: "msal-" + clientID,
	}
	// configure MSAL
	s.cli, err = public.New(clientID,
		public.WithAuthority(authority),
		public.WithCache(s.dvc),
		public.WithHTTPClient(hc),
	)
	if err != nil {
		return nil, err
	}
	return oauth2.ReuseTokenSource(nil, s), nil
}

func (s *azureSource) Token() (*oauth2.Token, error) {
	ctx := context.Background()
	// use cached token or silently refresh
	if acc, err := s.cli.Accounts(ctx); len(acc) != 0 {
		token, err := s.acquireSilent(ctx, acc[0], false)
		if err == nil && !token.Valid() {
			// MSAL gave us an expired ID token because it only looks at the access token.
			// Since it doesn't surface any better options to force a refresh,
			// wipe its cached access tokens.
			log.Println("warning: MSAL returned an expired ID token, forcing a refresh")
			token, err = s.acquireSilent(ctx, acc[0], true)
		}
		if err == nil {
			return token, nil
		}
		log.Println("warning: failed to refresh cached token:", err)
		// fallback
	} else if err != nil {
		return nil, fmt.Errorf("enumerating cached accounts: %w", err)
	}
	// use browser to interactively authenticate
	fmt.Fprintln(os.Stderr, "attempting interactive login")
	result, err := s.cli.AcquireTokenInteractive(ctx, s.scopes,
		public.WithOpenURL(s.openURL),
	)
	if err == nil {
		return s.toToken(result)
	} else if !errors.As(err, new(*exec.ExitError)) && !errors.As(err, new(*exec.Error)) {
		return nil, err
	}
	// use device code
	fmt.Fprintln(os.Stderr, "attempting device code login")
	dc, err := s.cli.AcquireTokenByDeviceCode(ctx, s.scopes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dc.Result.Message)
	fmt.Fprintln(os.Stderr)
	result, err = dc.AuthenticationResult(ctx)
	if err != nil {
		return nil, err
	}
	return s.toToken(result)
}

func (s *azureSource) acquireSilent(ctx context.Context, account public.Account, force bool) (*oauth2.Token, error) {
	s.dvc.wipeAccessTokens = force
	result, err := s.cli.AcquireTokenSilent(ctx, s.scopes, public.WithSilentAccount(account))
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

func (s *azureSource) openURL(url string) error {
	// devcontainers may have a helper to open a browser on the host
	if v := os.Getenv("BROWSER"); v != "" {
		fmt.Fprintln(os.Stderr, "Opening using $BROWSER:\n", url)
		cmd := exec.Command(v, url)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	fmt.Fprintln(os.Stderr, "Opening using default browser:\n", url)
	return browser.OpenURL(url)
}

// dvCache adapts the diskv key-value store to act as MSAL's persistence layer
type dvCache struct {
	dv  *diskv.Diskv
	key string

	wipeAccessTokens bool
}

func (c *dvCache) Export(_ context.Context, cache cache.Marshaler, _ cache.ExportHints) error {
	data, err := cache.Marshal()
	if err != nil {
		return err
	}
	return c.dv.Write(c.key, data)
}

func (c *dvCache) Replace(_ context.Context, cache cache.Unmarshaler, _ cache.ReplaceHints) error {
	data, err := c.dv.Read(c.key)
	if errors.Is(err, fs.ErrNotExist) {
		// cache miss
		return nil
	} else if err != nil {
		return err
	}
	if c.wipeAccessTokens {
		// Force MSAL to refresh by wiping its cached access tokens.
		var d map[string]any
		if err := json.Unmarshal(data, &d); err != nil {
			return err
		}
		delete(d, "AccessToken")
		delete(d, "IdToken")
		data, err = json.Marshal(d)
		if err != nil {
			return err
		}
	}
	return cache.Unmarshal(data)
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
