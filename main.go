package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"compute-go-auth/config"
	"compute-go-auth/cookie"
	"compute-go-auth/debug"

	"github.com/fastly/compute-sdk-go/fsthttp"
	"github.com/golang-jwt/jwt/v5"
)

// Set debug logging to false by default
const DEBUG = false

// PKCEChallenge represents a PKCE challenge with code verifier and code challenge
type PKCEChallenge struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
}

// JWTValidationOptions contains options for JWT validation
type JWTValidationOptions struct {
	Issuer   string
	Audience string
}

// TokenResponse represents the response from the OAuth 2.0 token endpoint
type TokenResponse struct {
	OK           bool   `json:"-"`
	Error        string `json:"error,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// UserInfoResponse represents the response from the OpenID Connect userinfo endpoint
type UserInfoResponse struct {
	OK            bool   `json:"-"`
	Error         string `json:"error,omitempty"`
	Sub           string `json:"sub,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Locale        string `json:"locale,omitempty"`
}

// generatePKCEChallenge generates a PKCE code verifier and code challenge using standard library
func generatePKCEChallenge() (*PKCEChallenge, error) {
	// Generate a random code verifier (43 characters as per RFC 7636)
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Generate the code challenge using SHA256
	codeChallenge := generateCodeChallenge(codeVerifier)

	return &PKCEChallenge{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}, nil
}

// generateCodeVerifier generates a random code verifier using crypto/rand
func generateCodeVerifier() (string, error) {
	const codeVerifierLength = 43
	bytes := make([]byte, codeVerifierLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:codeVerifierLength], nil
}

// generateCodeChallenge generates a code challenge from a code verifier using crypto/sha256
func generateCodeChallenge(codeVerifier string) string {
	// Hash the code verifier with SHA256
	hash := sha256.Sum256([]byte(codeVerifier))
	// Encode as base64url (without padding)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// generateRandomStr generates a random string using crypto/rand
func generateRandomStr(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

// getJWK retrieves a JWK from the JWKS
func getJWK(jwks *config.JWKS, kid string) (*config.JWK, error) {
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Looking for JWK with kid: %s\n", kid)
		fmt.Fprintf(os.Stdout, "Available JWKs: %d\n", len(jwks.Keys))
		for i, key := range jwks.Keys {
			fmt.Fprintf(os.Stdout, "  JWK %d: kid=%s, kty=%s, use=%s\n", i, key.Kid, key.Kty, key.Use)
		}
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			if debug.LOG {
				fmt.Fprintf(os.Stdout, "Found matching JWK for kid: %s\n", kid)
			}
			return &key, nil
		}
	}

	if debug.LOG {
		fmt.Fprintf(os.Stderr, "No matching JWK found for kid: %s\n", kid)
	}
	return nil, fmt.Errorf("no matching JWK found for identifier %s", kid)
}

// jwkToRSAPublicKey converts a JWK to an RSA public key using standard library
func jwkToRSAPublicKey(jwk *config.JWK) (*rsa.PublicKey, error) {
	// Decode the modulus and exponent
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert modulus to big.Int
	n := new(big.Int)
	n.SetBytes(nBytes)

	// Convert exponent to int
	e := new(big.Int)
	e.SetBytes(eBytes)

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return publicKey, nil
}

// validateJWT validates a JWT and verifies its claims using standard library
func validateJWT(jwks *config.JWKS, tokenString string, options *JWTValidationOptions) error {
	// Parse the token without verification to get the header
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Decode the header to get the key ID
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}

	if debug.LOG {
		fmt.Fprintf(os.Stdout, "JWT validation - kid: %s, alg: %s\n", header.Kid, header.Alg)
	}

	// Retrieve the public key matching the key ID
	jwk, err := getJWK(jwks, header.Kid)
	if err != nil {
		return fmt.Errorf("failed to get JWK: %w", err)
	}

	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Found JWK for kid: %s\n", header.Kid)
	}

	// Convert JWK to RSA public key
	publicKey, err := jwkToRSAPublicKey(jwk)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to RSA public key: %w", err)
	}

	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Converted JWK to RSA public key successfully\n")
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		if debug.LOG {
			fmt.Fprintf(os.Stderr, "JWT parsing failed: %v\n", err)
		}
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		if debug.LOG {
			fmt.Fprintf(os.Stderr, "JWT is not valid\n")
		}
		return fmt.Errorf("invalid JWT")
	}

	if debug.LOG {
		fmt.Fprintf(os.Stdout, "JWT signature validation successful\n")
	}

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid JWT claims")
	}

	if debug.LOG {
		fmt.Fprintf(os.Stdout, "JWT claims: %+v\n", claims)
	}

	// Verify issuer if provided
	if options.Issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != options.Issuer {
			if debug.LOG {
				fmt.Fprintf(os.Stderr, "Issuer mismatch - expected: %s, got: %s\n", options.Issuer, iss)
			}
			return fmt.Errorf("invalid issuer")
		}
		if debug.LOG {
			fmt.Fprintf(os.Stdout, "Issuer validation successful\n")
		}
	}

	// Verify audience if provided
	if options.Audience != "" {
		if aud, ok := claims["aud"].(string); !ok || aud != options.Audience {
			if debug.LOG {
				fmt.Fprintf(os.Stderr, "Audience mismatch - expected: %s, got: %s\n", options.Audience, aud)
			}
			return fmt.Errorf("invalid audience")
		}
		if debug.LOG {
			fmt.Fprintf(os.Stdout, "Audience validation successful\n")
		}
	}

	return nil
}

// generateNonceFromState creates a time-limited nonce JWT and encodes the passed state within its claims
func generateNonceFromState(nonceSecret []byte, state string) (string, string, error) {
	// Generate a random nonce
	nonce := generateRandomStr(30)

	// Create JWT claims
	now := time.Now()
	claims := jwt.MapClaims{
		"nonce": nonce,
		"sub":   state,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(), // 5 minutes expiration
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token
	tokenString, err := token.SignedString(nonceSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign nonce JWT: %w", err)
	}

	return tokenString, nonce, nil
}

// getClaimedState verifies the nonce JWT and retrieves its subject claim
func getClaimedState(nonceSecret []byte, stateAndNonce string) (string, error) {
	// Parse and validate the token
	token, err := jwt.Parse(stateAndNonce, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return nonceSecret, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to parse nonce JWT: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid nonce JWT")
	}

	// Extract the subject claim
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid JWT claims")
	}

	subject, ok := claims["sub"].(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid subject claim")
	}

	return subject, nil
}

// clearAllCookies expires all authentication cookies to clear any existing state
// This ensures a clean slate for the next authentication attempt
func clearAllCookies(w fsthttp.ResponseWriter) {
	cookie.SetCookie(w, "access_token", "expired", 0)
	cookie.SetCookie(w, "id_token", "expired", 0)
	cookie.SetCookie(w, "code_verifier", "expired", 0)
	cookie.SetCookie(w, "state", "expired", 0)
}

// The entry point for your application.
//
// This Fastly Compute@Edge application implements OAuth 2.0 Authorization Code flow
// with PKCE (Proof Key for Code Exchange) for secure authentication.
//
// Flow:
// 1. Unauthenticated requests are redirected to OAuth provider (Google)
// 2. User authenticates with provider and grants permissions
// 3. Provider redirects back to callback with authorization code
// 4. Application exchanges code for access and ID tokens
// 5. Tokens are validated and stored as secure cookies
// 6. Subsequent requests use tokens for authentication
func main() {

	debug.LOG = DEBUG

	// Log service version for debugging and monitoring
	fmt.Fprintln(os.Stdout, "FASTLY_SERVICE_VERSION:", os.Getenv("FASTLY_SERVICE_VERSION"))

	// Register the main request handler with Fastly
	fsthttp.ServeFunc(func(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
		handleRequest(ctx, w, r)
	})
}

// handleRequest is the main request router that handles all incoming requests
// It determines whether to start OAuth flow, handle callback, or process authenticated requests
func handleRequest(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
	// Load OAuth configuration from environment variables or Fastly Secret Store
	settings, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to load config:", err)
		w.WriteHeader(fsthttp.StatusInternalServerError)
		fmt.Fprintln(w, "Configuration error")
		return
	}

	// Parse cookies from the request to check for existing authentication
	cookies := cookie.Parse(r.Header.Get("Cookie"))

	// Debug logging for cookie parsing
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Request path: %s, cookies parsed - access_token: %s, id_token: %s, state: %s, code_verifier: %s\n",
			r.URL.Path,
			func() string {
				if cookies.AccessToken != "" {
					return cookies.AccessToken[:10] + "..."
				} else {
					return "empty"
				}
			}(),
			func() string {
				if cookies.IDToken != "" {
					return cookies.IDToken[:10] + "..."
				} else {
					return "empty"
				}
			}(),
			cookies.State,
			cookies.CodeVerifier)
	}

	// Build the OAuth 2.0 redirect URI for the callback
	// This must match exactly what's registered in the OAuth provider
	redirectURI := fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.URL.Host, settings.Config.CallbackPath)

	// Debug logging
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "redirectURI: %s\n", redirectURI)
	}

	// Handle OAuth callback from the identity provider
	if strings.HasPrefix(r.URL.Path, settings.Config.CallbackPath) {
		handleCallback(ctx, w, r, settings, cookies, redirectURI)
		return
	}

	// Check if user is already authenticated by looking for valid tokens
	if cookies.AccessToken != "" && cookies.IDToken != "" {
		if debug.LOG {
			fmt.Fprintf(os.Stdout, "Found access_token and id_token cookies, attempting authenticated request\n")
		}
		// Try to handle as authenticated request
		if handleAuthenticatedRequest(ctx, w, r, settings, cookies) {
			return
		}
	} else {
		if debug.LOG {
			fmt.Fprintf(os.Stdout, "No access_token or id_token cookies found, starting OAuth flow\n")
		}
	}

	// If not authenticated, start the OAuth 2.0 authorization code flow
	startOAuthFlow(ctx, w, r, settings, redirectURI)
}

// handleCallback processes the OAuth callback from the identity provider
// It validates the state parameter, exchanges the authorization code for tokens,
// and redirects the user back to their original request
func handleCallback(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request, settings *config.Settings, cookies *cookie.Cookies, redirectURI string) {
	// Debug logging
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Callback received - cookies: state=%s, code_verifier=%s\n", cookies.State, cookies.CodeVerifier)
	}

	// Verify that we have the required cookies from the OAuth initiation
	// These cookies contain the state and code_verifier needed for security
	if cookies.State == "" || cookies.CodeVerifier == "" {
		fmt.Fprintln(os.Stderr, "State or code_verifier cookies not found")
		// Return 401 Unauthorized with expired cookies
		w.WriteHeader(fsthttp.StatusUnauthorized)
		fmt.Fprintln(w, "State cookies not found.")
		clearAllCookies(w)
		return
	}

	// Extract query parameters from the identity provider's response
	qs := r.URL.Query()
	code := qs.Get("code")   // Authorization code to exchange for tokens
	state := qs.Get("state") // State parameter to prevent CSRF attacks

	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Callback params - code=%s, state=%s\n", code, state)
	}

	// Validate the state JWT returned by the identity provider
	// This prevents CSRF attacks by ensuring the state matches what we sent
	claimedState, err := getClaimedState(settings.Config.NonceSecret, state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not verify state:", err)
		// Return 401 Unauthorized with expired cookies
		w.WriteHeader(fsthttp.StatusUnauthorized)
		fmt.Fprintln(w, "Could not verify state.")
		clearAllCookies(w)
		return
	}

	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Claimed state: %s, stored state: %s\n", claimedState, cookies.State)
	}

	// Ensure the claimed state matches our stored state
	if claimedState != cookies.State {
		fmt.Fprintln(os.Stderr, "State mismatch")
		// Return 401 Unauthorized with expired cookies
		w.WriteHeader(fsthttp.StatusUnauthorized)
		fmt.Fprintln(w, "State mismatch.")
		clearAllCookies(w)
		return
	}

	// Exchange the authorization code for access and ID tokens
	// This is the core of the OAuth 2.0 authorization code flow
	exchangeRes, err := exchangeCodeForTokens(ctx, settings, code, cookies.CodeVerifier, redirectURI)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Token exchange failed:", err)
		// Return 401 Unauthorized with expired cookies
		w.WriteHeader(fsthttp.StatusUnauthorized)
		fmt.Fprintln(w, "Token exchange failed.")
		clearAllCookies(w)
		return
	}

	if !exchangeRes.OK {
		fmt.Fprintf(os.Stderr, "Token exchange error: %s\n", exchangeRes.Error)
		// Return 401 Unauthorized with expired cookies
		w.WriteHeader(fsthttp.StatusUnauthorized)
		fmt.Fprintln(w, exchangeRes.Error)
		clearAllCookies(w)
		return
	}

	// Extract the original request path from the state cookie
	// The state contains the original path + random string for security
	originalReqPath := cookies.State[:len(cookies.State)-settings.Config.StateParameterLength]
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Original request path: %s\n", originalReqPath)
	}

	// Redirect back to the original request with the new tokens set as cookies
	// Set cookies BEFORE writing headers
	cookie.SetCookie(w, "access_token", exchangeRes.AccessToken, exchangeRes.ExpiresIn)
	cookie.SetCookie(w, "id_token", exchangeRes.IDToken, exchangeRes.ExpiresIn)
	cookie.SetCookie(w, "code_verifier", "expired", 0) // Clear code verifier
	cookie.SetCookie(w, "state", "expired", 0)         // Clear state

	// Set the redirect location and write the response headers
	w.Header().Set("Location", originalReqPath)
	w.WriteHeader(fsthttp.StatusTemporaryRedirect)
	fmt.Fprintf(w, "Redirecting to %s", originalReqPath)
}

// handleAuthenticatedRequest processes requests from authenticated users
// It validates the access and ID tokens, then forwards the request to the origin backend
func handleAuthenticatedRequest(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request, settings *config.Settings, cookies *cookie.Cookies) bool {
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Handling authenticated request - access_token: %s, id_token: %s\n",
			cookies.AccessToken[:10]+"...", cookies.IDToken[:10]+"...")
	}

	// Validate the access token if introspection is enabled
	if settings.Config.IntrospectAccessToken {
		// Validate access token by calling the introspection endpoint
		userInfo, err := fetchUserInfo(ctx, settings, cookies.AccessToken)
		if err != nil || !userInfo.OK {
			if debug.LOG {
				fmt.Fprintf(os.Stdout, "Access token validation failed\n")
			}
			// Return 401 Unauthorized with expired cookies
			w.WriteHeader(fsthttp.StatusUnauthorized)
			fmt.Fprintln(w, "Access token validation failed.")
			clearAllCookies(w)
			return false
		}
		if debug.LOG {
			fmt.Fprintf(os.Stdout, "Access token validation successful\n")
		}
	} else if settings.Config.JWTAccessToken {
		// Validate JWT access token locally using JWKS
		err := validateJWT(settings.JWKS, cookies.AccessToken, &JWTValidationOptions{
			Issuer:   settings.OpenIDConfiguration.Issuer,
			Audience: settings.Config.ClientID,
		})
		if err != nil {
			if debug.LOG {
				fmt.Fprintf(os.Stdout, "Access token invalid\n")
			}
			// Return 401 Unauthorized with expired cookies
			w.WriteHeader(fsthttp.StatusUnauthorized)
			fmt.Fprintln(w, "Access token invalid.")
			clearAllCookies(w)
			return false
		}
		if debug.LOG {
			fmt.Fprintf(os.Stdout, "JWT access token validation successful\n")
		}
	}

	// Validate the ID token (JWT) using the provider's public keys
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Validating ID token with issuer: %s, audience: %s\n",
			settings.OpenIDConfiguration.Issuer, settings.Config.ClientID)
	}
	err := validateJWT(settings.JWKS, cookies.IDToken, &JWTValidationOptions{
		Issuer:   settings.OpenIDConfiguration.Issuer,
		Audience: settings.Config.ClientID,
	})
	if err != nil {
		if debug.LOG {
			fmt.Fprintf(os.Stdout, "ID token invalid\n")
		}
		// Return 401 Unauthorized with expired cookies
		w.WriteHeader(fsthttp.StatusUnauthorized)
		fmt.Fprintln(w, "ID token invalid.")
		clearAllCookies(w)
		return false
	}
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "ID token validation successful\n")
	}

	// Authentication successful! Forward the request to the origin backend
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Authentication successful, forwarding to origin\n")
	}

	// Add authentication headers for the origin backend
	if settings.Config.APIKey != "" {
		r.Header.Set("x-api-key", settings.Config.APIKey)
	}
	r.Header.Set("fastly-access-token", cookies.AccessToken)
	r.Header.Set("fastly-id-token", cookies.IDToken)

	// Forward the request to the origin backend
	resp, err := r.Send(ctx, "origin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Origin request failed:", err)
		w.WriteHeader(fsthttp.StatusBadGateway)
		fmt.Fprintln(w, "Origin request failed")
		return false
	}

	// Copy response headers from origin to client
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body from origin to client
	if resp.Body != nil {
		defer resp.Body.Close()
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}

	return true
}

// startOAuthFlow initiates the OAuth 2.0 authorization code flow
// It generates PKCE parameters, creates state tokens, and redirects to the identity provider
func startOAuthFlow(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request, settings *config.Settings, redirectURI string) {
	// Generate PKCE (Proof Key for Code Exchange) parameters
	// This prevents authorization code interception attacks
	pkceData, err := generatePKCEChallenge()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to generate PKCE challenge:", err)
		w.WriteHeader(fsthttp.StatusInternalServerError)
		fmt.Fprintln(w, "PKCE generation failed")
		return
	}

	// Generate state parameter with original request path embedded
	// This allows us to redirect back to the original request after authentication
	randState := generateRandomStr(settings.Config.StateParameterLength)
	sep := ""
	if r.URL.RawQuery != "" {
		sep = "?"
	}
	state := fmt.Sprintf("%s%s%s%s", r.URL.Path, sep, r.URL.RawQuery, randState)

	// Generate OpenID Connect nonce to prevent replay attacks
	// The nonce is embedded in the state JWT for security
	stateAndNonce, nonce, err := generateNonceFromState(settings.Config.NonceSecret, state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to generate nonce:", err)
		w.WriteHeader(fsthttp.StatusInternalServerError)
		fmt.Fprintln(w, "Nonce generation failed")
		return
	}

	// Build the authorization request URL for the identity provider
	authReqURL, err := url.Parse(settings.OpenIDConfiguration.AuthorizationEndpoint)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid authorization endpoint:", err)
		w.WriteHeader(fsthttp.StatusInternalServerError)
		fmt.Fprintln(w, "Configuration error")
		return
	}

	// Add OAuth 2.0 and OpenID Connect parameters to the authorization request
	q := authReqURL.Query()
	q.Set("client_id", settings.Config.ClientID)
	q.Set("code_challenge", pkceData.CodeChallenge)
	q.Set("code_challenge_method", settings.Config.CodeChallengeMethod)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", settings.Config.Scope)
	q.Set("state", stateAndNonce)
	q.Set("nonce", nonce)
	authReqURL.RawQuery = q.Encode()

	// Debug logging
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Starting OAuth flow - redirect_uri: %s\n", redirectURI)
		fmt.Fprintf(os.Stdout, "Setting cookies - state: %s, code_verifier: %s\n", state, pkceData.CodeVerifier)
		fmt.Fprintf(os.Stdout, "Authorization URL: %s\n", authReqURL.String())
	}

	// Set security cookies before redirecting
	// These cookies contain the state and code_verifier needed for the callback
	cookie.SetCookie(w, "code_verifier", pkceData.CodeVerifier, 600) // 10 minutes
	cookie.SetCookie(w, "state", state, 600)                         // 10 minutes

	// Redirect the user to the identity provider for authentication
	w.Header().Set("Location", authReqURL.String())
	w.WriteHeader(fsthttp.StatusTemporaryRedirect)
	fmt.Fprintf(w, "Redirecting to %s", authReqURL.String())
}

// exchangeCodeForTokens exchanges the authorization code for access and ID tokens
// This is the second step of the OAuth 2.0 authorization code flow
func exchangeCodeForTokens(ctx context.Context, settings *config.Settings, code, codeVerifier, redirectURI string) (*TokenResponse, error) {
	// Prepare the token exchange request body
	data := url.Values{}
	data.Set("client_id", settings.Config.ClientID)
	if settings.Config.ClientSecret != "" {
		data.Set("client_secret", settings.Config.ClientSecret)
	}
	data.Set("code", code)
	data.Set("code_verifier", codeVerifier) // PKCE code verifier
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURI) // Must match the authorization request

	// Debug logging (redact sensitive data)
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Token exchange - client_id: %s, redirect_uri: %s, code_verifier: %s\n",
			settings.Config.ClientID, redirectURI, codeVerifier)
		fmt.Fprintf(os.Stdout, "Token endpoint: %s\n", settings.OpenIDConfiguration.TokenEndpoint)
		fmt.Fprintf(os.Stdout, "Request body: %s\n", data.Encode())
	}

	// Create and send the token exchange request
	req, err := fsthttp.NewRequest("POST", settings.OpenIDConfiguration.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create token exchange request: %v\n", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request to the identity provider's token endpoint
	resp, err := req.Send(ctx, "idp")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send token exchange request: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Token exchange response status: %d\n", resp.StatusCode)
		fmt.Fprintf(os.Stdout, "Token exchange response headers: %v\n", resp.Header)
	}

	// Handle token exchange errors
	if resp.StatusCode != http.StatusOK {
		// Read error response body for debugging
		body := make([]byte, 4096) // Increased buffer size
		n, readErr := resp.Body.Read(body)
		if readErr != nil && readErr != io.EOF {
			fmt.Fprintf(os.Stderr, "Failed to read error response body: %v\n", readErr)
		}
		errorBody := string(body[:n])
		fmt.Fprintf(os.Stderr, "Token exchange error response (status %d): %s\n", resp.StatusCode, errorBody)
		return &TokenResponse{OK: false, Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, errorBody)}, nil
	}

	// Parse the successful token response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode token response: %v\n", err)
		return nil, err
	}

	tokenResp.OK = true
	if debug.LOG {
		fmt.Fprintf(os.Stdout, "Token exchange successful - access_token: %s, id_token: %s\n",
			tokenResp.AccessToken[:10]+"...", tokenResp.IDToken[:10]+"...")
	}
	return &tokenResp, nil
}

// fetchUserInfo retrieves user information from the OpenID Connect userinfo endpoint
// This is used to validate access tokens when introspection is enabled
func fetchUserInfo(ctx context.Context, settings *config.Settings, accessToken string) (*UserInfoResponse, error) {
	req, err := fsthttp.NewRequest("GET", settings.OpenIDConfiguration.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := req.Send(ctx, "idp")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &UserInfoResponse{OK: false}, nil
	}

	var userInfo UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	userInfo.OK = true
	return &userInfo, nil
}
