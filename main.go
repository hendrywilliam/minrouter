package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// Proxy configuration
const MIN_TCP_PORT = 1
const MAX_TCP_PORT = 65535
const DEFAULT_PROXY_TIMEOUT = 30
const DEFAULT_PROXY_PORT = "8080"

// Pod configuration
const DEFAULT_POD_PORT = "8888"
const DEFAULT_POD_NAMESPACE = "default"
const DEFAULT_CLUSTER_DOMAIN = "cluster.local"

var log = zerolog.New(os.Stdout).
	With().
	Timestamp().
	Caller().
	Logger()

var clusterDomain = getClusterDomain()
var dnsLabelRegex = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
var proxyTimeout = getProxyTimeout()
var routerAuthToken = os.Getenv("ROUTER_AUTH_TOKEN")
var allowAuthenticatedRouter = envVarIsTruthy("ALLOW_AUTHENTICATED_ROUTER")

func getProxyTimeout() float64 {
	raw := os.Getenv("PROXY_TIMEOUT_SECONDS")
	if raw == "" {
		log.Debug().Msg("PROXY_TIMEOUT_SECONDS not set, using default")
		return DEFAULT_PROXY_TIMEOUT
	}
	num, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		log.Warn().Str("value", raw).Err(err).Msg("invalid PROXY_TIMEOUT_SECONDS, falling back to default")
		return DEFAULT_PROXY_TIMEOUT
	}
	if num <= 0 {
		log.Warn().Float64("value", num).Msg("PROXY_TIMEOUT_SECONDS must be positive, falling back to default")
		return DEFAULT_PROXY_TIMEOUT
	}
	log.Info().Float64("timeout", num).Msg("proxy timeout configured")
	return num
}

func getClusterDomain() string {
	clusterDomain := os.Getenv("CLUSTER_DOMAIN")
	if clusterDomain == "" {
		log.Warn().Str("value", clusterDomain).Msg("WARNING: CLUSTER_DOMAIN must not be an empty string")
		return DEFAULT_CLUSTER_DOMAIN
	}
	return clusterDomain
}

func getRequestTimeout(h *http.Request) float64 {
	raw := h.Header.Get("X-Router-Timeout")
	if raw == "" {
		return proxyTimeout
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		log.Warn().Str("value", raw).Err(err).Msg("failed to parse X-Router-Timeout value, falling back to default")
		return proxyTimeout
	}
	if math.IsInf(value, 0) || math.IsNaN(value) || value <= 0 {
		log.Warn().Str("value", raw).Err(err).Msg("X-Router-Timeout must be finite and positive, falling back to default")
		return proxyTimeout
	}
	if value > proxyTimeout {
		log.Warn().Str("value", raw).Err(err).Msg("X-Router-Timeout exceeds configured, capping to default.")
		return proxyTimeout
	}
	return value
}

func isValidDnsLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	return dnsLabelRegex.Match([]byte(label))
}

func envVarIsTruthy(name string) bool {
	raw := os.Getenv(name)
	if raw == "" {
		return false
	}
	truthyValues := []string{"1", "true", "yes", "y"}
	rawL := strings.ToLower(raw)
	return slices.Contains(truthyValues, rawL)
}

func proxyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if allowAuthenticatedRouter {
			routerToken := c.Request.Header.Get("X-Router-Token")
			if routerToken == "" {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "X-Router-Token header is required",
				})
				return
			}
			result := subtle.ConstantTimeCompare([]byte(routerToken), []byte(routerAuthToken))
			if result == 1 {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Invalid X-Router-Token value",
			})
			return
		}
		c.Next()
	}
}

func proxyHandler(c *gin.Context) {
	allowedMethods := []string{"get", "post", "put", "delete", "patch"}
	if !slices.Contains(allowedMethods, strings.ToLower(c.Request.Method)) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{
			"error": "method is not allowed",
		})
		return
	}

	podId := c.Request.Header.Get("X-Pod-ID")
	if podId == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "X-Pod-ID is required",
		})
		return
	}

	// Sanitize to prevent DNS injection.
	if !isValidDnsLabel(podId) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "invalid Pod id format",
		})
		return
	}

	namespace := c.Request.Header.Get("X-Pod-Namespace")
	if namespace == "" {
		namespace = DEFAULT_POD_NAMESPACE
	}

	// Sanitize to prevent DNS injection.
	if !isValidDnsLabel(namespace) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "invalid Pod namespace format",
		})
		return
	}

	strPort := c.Request.Header.Get("X-Pod-Port")
	if strPort == "" {
		strPort = DEFAULT_POD_PORT
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "invalid X-Pod-Port format",
		})
		return
	}
	if !(MIN_TCP_PORT <= port && port <= MAX_TCP_PORT) {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
			"error": "invalid X-Pod-Port format",
		})
		return
	}

	var targetHost strings.Builder
	// Final result will be: podId.podNamespace.svc.cluster.local
	var internalDNSName []string = []string{
		podId,
		namespace,
		"svc",
		clusterDomain,
	}

	// Dynamic routing.
	// Route by Pod IP if provided by client,
	// otherwise fallback to DNS name and leveraging CoreDNS DNS resolution.
	podIP := c.Request.Header.Get("X-Pod-IP")
	if podIP != "" {
		ip := net.ParseIP(podIP)
		// IsLoopBack reports whether ip is a loopback address
		// for instance: 127.0.0.1 (resolve to localhost, IPv4) or ::1 (IPv6)
		// IsLinkLocalUnicast reports whether ip is a link-local unicast address
		// IsMulticast report whether ip is a multicast address
		// IsUnspecified reports unspecified address. IPv4 0.0.0.0 and IPv6 ::
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "invalid X-Pod-IP format",
			})
			return
		}
		targetHost.WriteString(ip.String())
	} else {
		targetHost.WriteString(strings.Join(internalDNSName, "."))
	}
	targetHostStr := net.JoinHostPort(targetHost.String(), strPort)
	targetURL := &url.URL{
		Scheme: "http",
		Host:   targetHostStr,
	}
	timeout := time.Duration(getRequestTimeout(c.Request) * float64(time.Second))
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = targetURL.Scheme
			pr.Out.URL.Host = targetURL.Host
			pr.Out.Host = targetURL.Host
			for key, values := range pr.In.Header {
				for _, v := range values {
					pr.Out.Header.Add(key, v)
				}
			}
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Host", c.Request.Host)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Op == "dial" {
				log.Error().Str("target", targetHostStr).Err(err).Msg("connection to pod failed")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(gin.H{
					"error": "Could not connect to the backend pod",
				})
				return
			}
			if errors.As(err, &opErr) && opErr.Timeout() {
				log.Error().Str("target", targetHostStr).Err(err).Msg("request to pod timed out")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusGatewayTimeout)
				json.NewEncoder(w).Encode(gin.H{
					"error": "Timed out waiting for the backend pod",
				})
				return
			}
			log.Error().Str("target", targetHostStr).Err(err).Msg("unexpected proxy error")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(gin.H{
				"error": "An internal error occurred in the proxy",
			})
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: timeout,
		},
	}

	log.Info().
		Str("host", targetURL.Host).
		Str("path", c.Request.URL.Path).
		Str("method", c.Request.Method).
		Str("pod", podId).
		Msg("proxying request")

	proxy.ServeHTTP(c.Writer, c.Request)
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	if allowAuthenticatedRouter {
		log.Info().Msg("Authentication enabled. request must include valid X-Router-Token header.")
	} else {
		log.Warn().Msg("WARNING: Running in UNAUTHENTICATED mode because allow authenticated router is disabled.")
	}
	r := gin.New()
	r.Use(logger.SetLogger(
		logger.WithLogger(func(c *gin.Context, l zerolog.Logger) zerolog.Logger {
			return log
		}),
	))
	r.Use(gin.Recovery())
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "OK",
		})
	})
	r.Use(proxyAuthMiddleware())
	r.NoRoute(proxyHandler)

	srv := &http.Server{
		Addr:    ":" + DEFAULT_PROXY_PORT,
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("failed to start server")
		}
	}()
	log.Info().Str("port", DEFAULT_PROXY_PORT).Msg("server started")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("forced server shutdown")
	}
	log.Info().Msg("server exited")
}
