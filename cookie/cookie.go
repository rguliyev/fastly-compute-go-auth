package cookie

import (
	"os"
	"strings"
	"time"

	"compute-go-auth/log"

	"github.com/fastly/compute-sdk-go/fsthttp"
)

// Cookies represents the OAuth 2.0 cookies used throughout the authentication flow
// These cookies store sensitive authentication data and must be handled securely
type Cookies struct {
	AccessToken  string // OAuth 2.0 access token for API access
	IDToken      string // OpenID Connect ID token for user identity
	CodeVerifier string // PKCE code verifier for authorization code exchange
	State        string // OAuth state parameter with embedded request path
}

// Parse parses cookies from the HTTP Cookie header
// It handles cookie prefixes for different environments (local vs production)
// and extracts OAuth-related cookies for authentication
func Parse(cookieHeader string) *Cookies {
	// Debug logging for cookie parsing
	log.Debug("Parsing cookies from header: %s", cookieHeader)

	// Return empty cookies if no cookie header is present
	if cookieHeader == "" {
		log.Debug("No cookie header found")
		return &Cookies{}
	}

	cookies := &Cookies{}
	prefix := getPrefix()
	log.Debug("Using cookie prefix: %s", prefix)

	// Parse the cookie header manually by splitting on semicolons
	// This handles cookies that may contain commas in their values
	pairs := strings.Split(cookieHeader, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		// Split each cookie into name and value
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := parts[0]
		value := parts[1]

		log.Debug("Found cookie: %s=%s", name, value)

		// In production, only process cookies with the correct prefix
		// This prevents cookie confusion attacks and ensures security
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			log.Debug("Skipping cookie %s (doesn't match prefix %s)", name, prefix)
			continue
		}

		// Remove the environment-specific prefix from cookie names
		// This allows the same code to work in both local and production
		if prefix != "" && strings.HasPrefix(name, prefix) {
			name = name[len(prefix):]
			log.Debug("Removed prefix, cookie name: %s", name)
		}

		// Map cookie names to their corresponding fields
		switch name {
		case "access_token":
			cookies.AccessToken = value
			log.Debug("Set access_token: %s", value)
		case "id_token":
			cookies.IDToken = value
			log.Debug("Set id_token: %s", value)
		case "code_verifier":
			cookies.CodeVerifier = value
			log.Debug("Set code_verifier: %s", value)
		case "state":
			cookies.State = value
			log.Debug("Set state: %s", value)
		}
	}

	log.Debug("Final parsed cookies: state=%s, code_verifier=%s",
		cookies.State, cookies.CodeVerifier)
	return cookies
}

// SetCookie sets a cookie on the HTTP response with appropriate security attributes
// It automatically adds environment-specific prefixes and security flags
func SetCookie(w fsthttp.ResponseWriter, name, value string, maxAge int) {
	prefix := getPrefix()
	cookieName := prefix + name

	// Create cookie with security best practices
	cookie := &fsthttp.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",                     // Available across the entire domain
		Secure:   isSecure(),              // HTTPS only in production
		HttpOnly: true,                    // Prevent XSS attacks
		SameSite: fsthttp.SameSiteLaxMode, // CSRF protection
	}

	// Set expiration time based on maxAge parameter
	if maxAge > 0 {
		cookie.Expires = time.Now().Add(time.Duration(maxAge) * time.Second)
	} else if maxAge == 0 {
		// maxAge = 0 means delete the cookie immediately
		cookie.Expires = time.Unix(0, 0)
	}

	// Debug logging for cookie setting
	log.Debug("Setting cookie: %s=%s (prefix=%s, secure=%t, maxAge=%d)",
		cookieName, value, prefix, isSecure(), maxAge)

	// Add the cookie to the response headers
	fsthttp.SetCookie(w.Header(), cookie)
}

// getPrefix returns the appropriate cookie prefix based on the environment
// In production (Fastly), cookies use the "__Secure-" prefix for additional security
// In local development, cookies use the "local-" prefix for easier debugging
func getPrefix() string {
	// Check if we're running in Fastly production environment
	if os.Getenv("FASTLY_SERVICE_VERSION") != "" && os.Getenv("FASTLY_SERVICE_VERSION") != "0" {
		return "__Secure-" // Production: requires HTTPS and secure context
	}
	return "local-" // Local development: easier to work with
}

// isSecure returns whether cookies should be marked as secure
// Secure cookies are only sent over HTTPS connections
func isSecure() bool {
	// Only set Secure flag in production environment
	// This allows local development over HTTP
	v := os.Getenv("FASTLY_SERVICE_VERSION")
	return v != "" && v != "0"
}
