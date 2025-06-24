package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fastly/compute-sdk-go/configstore"
	"github.com/fastly/compute-sdk-go/secretstore"
)

// Fastly store names for configuration and secrets
// These stores are configured in the Fastly dashboard
const (
	ConfigStoreName = "oauth_config"  // Store for non-sensitive configuration
	SecretStoreName = "oauth_secrets" // Store for sensitive secrets
)

// Settings contains all configuration needed for OAuth 2.0 authentication
// This struct holds the complete configuration loaded from Fastly stores
type Settings struct {
	Config              *ServiceConfig       // OAuth 2.0 service configuration
	JWKS                *JWKS                // JSON Web Key Set for token validation
	OpenIDConfiguration *OpenIDConfiguration // OpenID Connect discovery document
}

// ServiceConfig contains OAuth 2.0 service configuration
// This includes client credentials, endpoints, and security settings
type ServiceConfig struct {
	ClientID              string // OAuth 2.0 client identifier
	ClientSecret          string // OAuth 2.0 client secret (optional for public clients)
	IntrospectAccessToken bool   // Whether to validate access tokens via userinfo endpoint
	JWTAccessToken        bool   // Whether access tokens are JWTs that can be validated locally
	CallbackPath          string // OAuth callback endpoint path
	CodeChallengeMethod   string // PKCE code challenge method (S256)
	StateParameterLength  int    // Length of random state parameter
	Scope                 string // OAuth 2.0 scope string
	NonceSecret           []byte // Secret for signing/verifying nonce JWTs
	APIKey                string // API key for origin requests
}

// JWKS represents a JSON Web Key Set
// This contains the public keys used to validate JWT tokens
type JWKS struct {
	Keys []JWK `json:"keys"` // Array of JSON Web Keys
}

// JWK represents a JSON Web Key
// This is a single public key used for JWT signature verification
type JWK struct {
	Use string `json:"use"` // Key usage (sig/enc)
	Kid string `json:"kid"` // Key ID
	E   string `json:"e"`   // RSA exponent
	Alg string `json:"alg"` // Algorithm (RS256, etc.)
	N   string `json:"n"`   // RSA modulus
	Kty string `json:"kty"` // Key type (RSA, EC, etc.)
}

// OpenIDConfiguration represents the OpenID Connect discovery document
// This contains all the endpoints and capabilities of the OAuth provider
type OpenIDConfiguration struct {
	Issuer                   string   `json:"issuer"`                                // OAuth provider issuer URL
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`                // OAuth authorization endpoint
	TokenEndpoint            string   `json:"token_endpoint"`                        // OAuth token endpoint
	UserinfoEndpoint         string   `json:"userinfo_endpoint"`                     // OpenID Connect userinfo endpoint
	JwksURI                  string   `json:"jwks_uri"`                              // JWKS endpoint URL
	ResponseTypesSupported   []string `json:"response_types_supported"`              // Supported response types
	SubjectTypesSupported    []string `json:"subject_types_supported"`               // Supported subject types
	IDTokenSigningAlgValues  []string `json:"id_token_signing_alg_values_supported"` // Supported signing algorithms
	ScopesSupported          []string `json:"scopes_supported"`                      // Supported OAuth scopes
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"` // Supported auth methods
	ClaimsSupported          []string `json:"claims_supported"`                      // Supported OpenID claims
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`      // Supported PKCE methods
	GrantTypesSupported      []string `json:"grant_types_supported"`                 // Supported grant types
}

// LoadConfig loads all configuration from Fastly's config store and secret store
// This function initializes the complete OAuth configuration needed for authentication
func LoadConfig() (*Settings, error) {
	// Load OAuth 2.0 service configuration (client ID, secrets, etc.)
	serviceConfig, err := loadServiceConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load service config: %w", err)
	}

	// Load JSON Web Key Set from config store
	// This contains the public keys for validating JWT tokens
	jwks, err := loadJSONFromConfigStore("jwks", &JWKS{})
	if err != nil {
		return nil, fmt.Errorf("failed to load JWKS: %w", err)
	}

	// Load OpenID Connect configuration from config store
	// This contains all the OAuth provider endpoints and capabilities
	openIDConfig, err := loadJSONFromConfigStore("openid_configuration", &OpenIDConfiguration{})
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenID configuration: %w", err)
	}

	return &Settings{
		Config:              serviceConfig,
		JWKS:                jwks.(*JWKS),
		OpenIDConfiguration: openIDConfig.(*OpenIDConfiguration),
	}, nil
}

// loadServiceConfig loads OAuth 2.0 service configuration
// Only loads from Fastly secret store and config store (no environment variables)
func loadServiceConfig() (*ServiceConfig, error) {
	// Always load from Fastly secret store (production and local)
	secret, err := secretstore.Plaintext(SecretStoreName, "client_id")
	if err != nil {
		return nil, fmt.Errorf("failed to get client_id from secret store: %w", err)
	}
	clientID := strings.TrimSpace(string(secret))

	secret, err = secretstore.Plaintext(SecretStoreName, "client_secret")
	clientSecret := ""
	if err == nil {
		clientSecret = strings.TrimSpace(string(secret))
	}

	secret, err = secretstore.Plaintext(SecretStoreName, "nonce_secret")
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce_secret from secret store: %w", err)
	}
	nonceSecret := strings.TrimSpace(string(secret))

	secret, err = secretstore.Plaintext(SecretStoreName, "api_key")
	apiKey := ""
	if err == nil {
		apiKey = strings.TrimSpace(string(secret))
	}

	// Load non-sensitive configuration from Fastly config store
	config, err := configstore.Open(ConfigStoreName)
	if err != nil {
		return nil, fmt.Errorf("failed to open config store: %w", err)
	}

	callbackPath, err := config.Get("callback_path")
	if err != nil {
		return nil, fmt.Errorf("failed to get callback_path: %w", err)
	}

	codeChallengeMethod, err := config.Get("code_challenge_method")
	if err != nil {
		return nil, fmt.Errorf("failed to get code_challenge_method: %w", err)
	}

	introspectAccessToken, err := config.Get("introspect_access_token")
	if err != nil {
		return nil, fmt.Errorf("failed to get introspect_access_token: %w", err)
	}

	jwtAccessToken, err := config.Get("jwt_access_token")
	if err != nil {
		return nil, fmt.Errorf("failed to get jwt_access_token: %w", err)
	}

	scope, err := config.Get("scope")
	if err != nil {
		return nil, fmt.Errorf("failed to get scope: %w", err)
	}

	return &ServiceConfig{
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		IntrospectAccessToken: introspectAccessToken == "true",
		JWTAccessToken:        jwtAccessToken == "true",
		CallbackPath:          string(callbackPath),
		CodeChallengeMethod:   string(codeChallengeMethod),
		StateParameterLength:  10, // Default value for random state parameter
		Scope:                 string(scope),
		NonceSecret:           []byte(nonceSecret),
		APIKey:                apiKey,
	}, nil
}

// loadJSONFromConfigStore loads and parses JSON data from the Fastly config store
// This is used for loading JWKS and OpenID configuration which are stored as JSON
func loadJSONFromConfigStore(key string, target interface{}) (interface{}, error) {
	// Open the config store
	store, err := configstore.Open(ConfigStoreName)
	if err != nil {
		return nil, fmt.Errorf("failed to open config store: %w", err)
	}

	// Get the JSON data from the store
	data, err := store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s from config store: %w", key, err)
	}

	// Parse the JSON data into the target struct
	if err := json.Unmarshal([]byte(data), target); err != nil {
		return nil, fmt.Errorf("failed to parse %s JSON: %w", key, err)
	}

	return target, nil
}

// GetServiceVersion returns the Fastly service version
// This is used to determine if we're running in production or development
func GetServiceVersion() string {
	return os.Getenv("FASTLY_SERVICE_VERSION")
}

// IsProduction returns true if running in production (has service version)
// This is used to determine environment-specific behavior
func IsProduction() bool {
	v := os.Getenv("FASTLY_SERVICE_VERSION")
	return v != "" && v != "0"
}
