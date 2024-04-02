package replace_token

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if bytes, err := json.Marshal(c.Headers); err == nil {
		c.Logger.Infof("Custom Headers: %s", string(bytes))
	}
	c.Logger.Infof("Cache file: %s", c.CacheFile)
	return nil
}

func (c *ReplaceToken) RandMachineId() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		c.Logger.Warn("Error generating random machine id: ", err)
	}

	str := hex.EncodeToString(bytes)
	return str
}

func (c *ReplaceToken) GetTokenInfo(token string) *TokenInfo {
	cachedInfo, exists := c.Cache[token]
	if exists && cachedInfo.ExpiresAt > time.Now().Unix() {
		return &cachedInfo
	}
	c.Logger.Info("Cache missed or expired. Fetching new token from ", c.AuthURL)
	req, err := http.NewRequest("GET", c.AuthURL, nil)
	if err != nil {
		c.Logger.Warn("Error creating request: ", err)
		return nil
	}
	if c.Headers != nil {
		for key, values := range c.Headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}
	if auth := req.Header.Get("Authorization"); auth == "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("Authorization", fmt.Sprintf(auth, token))
	}

	if bytes, err := json.Marshal(req.Header); err == nil {
		c.Logger.Debugf("Auth Request: %s %s %s", req.Method, req.URL, string(bytes))
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if bytes, err := json.Marshal(resp.Header); err == nil {
		c.Logger.Debugf("Auth Response: %s %s", resp.Status, string(bytes))
	}
	if err != nil {
		c.Logger.Warn("Error fetching token: ", err)
		return nil
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		c.Logger.Warnf("Unexpected response: %s %s %s", resp.Status, resp.Header, resp.Body)
		return nil
	}
	defer resp.Body.Close()

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		resp.Body, err = gzip.NewReader(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			c.Logger.Warn("Error decoding gzip body: ", err)
			return nil
		}
	case "":
		break
	default:
		c.Logger.Warn("Unsupported content encoding: ", resp.Header.Get("Content-Encoding"))
		return nil
	}
	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		c.Logger.Warn("Failed to decode response: ", err)
		bytes, _ := io.ReadAll(resp.Body)
		c.Logger.Warn("Response body: ", string(bytes))
		return nil
	}
	info := TokenInfo{
		Token:     authResponse.Token,
		ExpiresAt: authResponse.ExpiresAt,
		MachineId: c.RandMachineId(),
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
	if bytes, err := json.Marshal(r.Header); err == nil {
		c.Logger.Debugf("Request: %s %s %s", r.Method, r.URL, string(bytes))
	}
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
	unixMillis := time.Now().UnixNano() / 1e6
	r.Header.Set("Authorization", "Bearer "+info.Token)
	r.Header.Set("X-Request-Id", uuid.NewString())
	r.Header.Set("Vscode-Sessionid", info.SessionId+strconv.FormatInt(unixMillis, 10))
	r.Header.Set("Vscode-Machineid", info.MachineId)

	if bytes, err := json.Marshal(r.Header); err == nil {
		c.Logger.Debugf("Modified request: %s %s %s", r.Method, r.URL, string(bytes))
	}
	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*ReplaceToken)(nil)
	_ caddy.Validator             = (*ReplaceToken)(nil)
	_ caddyhttp.MiddlewareHandler = (*ReplaceToken)(nil)
)
