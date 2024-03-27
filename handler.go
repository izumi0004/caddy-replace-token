package replace_token

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ReplaceToken{})
}

type AuthResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

type TokenInfo struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	MachineId string `json:"machine_id"`
	SessionId string `json:"session_id"`
}

type ReplaceToken struct {
	AuthURL   string      `json:"auth_url,omitempty"`
	Headers   http.Header `json:"headers"`
	CacheFile string      `json:"cache_file,omitempty"`

	Cache  map[string]TokenInfo
	Logger *zap.SugaredLogger
}

// CaddyModule returns the Caddy module information.
func (ReplaceToken) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.replace_token",
		New: func() caddy.Module { return new(ReplaceToken) },
	}
}

// Provision implements caddy.Provisioner.
func (c *ReplaceToken) Provision(ctx caddy.Context) error {
	c.Logger = ctx.Logger().Sugar()
	if c.AuthURL == "" {
		c.Logger.Error("Auth URL is required")
		return errors.New("invalid argument")
	}
	if c.CacheFile != "" {
		// Load cache from file
		file, err := os.Open(c.CacheFile)
		if err != nil {
			c.Logger.Warn("Error opening cache file: ", err)
		} else {
			defer file.Close()
			if err := json.NewDecoder(file).Decode(&c.Cache); err != nil {
				c.Logger.Warn("Error decoding cache file: ", err)
			}
		}
	}
	if c.Cache == nil {
		c.Cache = make(map[string]TokenInfo)
	}
	return nil
}

func (c ReplaceToken) Validate() error {
	c.Logger.Infof("Initialized with auth URL: %s", c.AuthURL)
	return nil
}

func (c *ReplaceToken) GetTokenInfo(token string) *TokenInfo {
	cachedInfo, exists := c.Cache[token]
	if exists && cachedInfo.ExpiresAt > time.Now().Unix() {
		return &cachedInfo
	}
	c.Logger.Infof("Cache missed or expired. Fetching new token from %s", c.AuthURL)
	req, err := http.NewRequest("GET", c.AuthURL, nil)
	if err != nil {
		c.Logger.Warn("Error creating request: ", err)
		return nil
	}
	if c.Headers != nil {
		req.Header = c.Headers
	}
	req.Header.Set("Authorization", "Bearer "+token)
	c.Logger.Debug("Auth Request: ", req.Method, req.URL, req.Header)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.Logger.Warn("Error fetching token: ", err)
		return nil
	}
	defer resp.Body.Close()
	c.Logger.Debug("Auth Response: ", resp.Status, resp.Header)

	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		c.Logger.Warn("Unable to get token: ", err, ". Response: ", resp)
		return nil
	}
	info := TokenInfo{
		Token:     authResponse.Token,
		ExpiresAt: authResponse.ExpiresAt,
		MachineId: uuid.NewString(),
		SessionId: uuid.NewString(),
	}
	if exists {
		info.MachineId = cachedInfo.MachineId
	}
	c.Cache[token] = info
	location, err := time.LoadLocation("Local")
	if err != nil {
		c.Logger.Warn("Error loading location: ", err)
		c.Logger.Infof("Fetched new token")
	} else {
		expire_at := time.Unix(info.ExpiresAt, 0).In(location).Format(time.RFC3339)
		ratelimit := resp.Header.Get("X-Ratelimit-Limit")
		ratelimit_used := resp.Header.Get("X-Ratelimit-Used")
		ratelimit_reset, err := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Reset"), 10, 64)
		reset_at := ""
		if err == nil {
			reset_at = time.Unix(ratelimit_reset, 0).In(location).Format(time.RFC3339)
		}
		c.Logger.Infof("Fetched new token, expiration time: %s, rate limit: %s/%s, reset time: %s", expire_at, ratelimit_used, ratelimit, reset_at)
	}

	if c.CacheFile != "" {
		go func() {
			file, err := os.Create(c.CacheFile)
			if err != nil {
				c.Logger.Warn("Error creating cache file: ", err)
				return
			}
			defer file.Close()
			if err := json.NewEncoder(file).Encode(c.Cache); err != nil {
				c.Logger.Warn("Error encoding cache file: ", err)
			}
			file.Sync()
		}()
	}

	return &info
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (c *ReplaceToken) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	c.Logger.Debug("Request: ", r.Method, r.URL, r.Header)
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		c.Logger.Warn("Missing token in request")
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	token := header[7:]
	info := c.GetTokenInfo(token)
	if info == nil {
		c.Logger.Warnf("Invalid token: %s", token)
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	r.Header.Set("Authorization", "Bearer "+info.Token)
	r.Header.Set("X-Request-Id", uuid.NewString())
	r.Header.Set("Vscode-Sessionid", info.SessionId)
	r.Header.Set("Vscode-Machineid", info.MachineId)

	c.Logger.Debug("Modified request: ", r.Method, r.URL, r.Header)
	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*ReplaceToken)(nil)
	_ caddy.Validator             = (*ReplaceToken)(nil)
	_ caddyhttp.MiddlewareHandler = (*ReplaceToken)(nil)
)
