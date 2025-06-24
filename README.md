# OAuth 2.0 Go Application Starter Kit for Fastly Compute

Connect to an identity provider such as Google using OAuth 2.0 and validate authentication status at the network's edge, using [Fastly Compute](https://www.fastly.com/products/edge-compute) to authorize access to your edge or origin hosted applications.

**For more starter kits for Compute, head over to the [Fastly Documentation Hub](https://www.fastly.com/documentation/solutions/starters)**

> This starter kit has an [equivalent Rust implementation](https://github.com/fastly/compute-rust-auth) 🟨

---

## Overview

This project is a self-contained Go implementation of the [OAuth 2.0 Authorization Code flow](https://oauth.net/2/grant-types/authorization-code/) with [PKCE](https://oauth.net/2/pkce/), designed for deployment on [Fastly Compute](https://www.fastly.com/products/edge-compute/). It includes:

- Secure OAuth 2.0 login with any OIDC-compliant provider (e.g., Google)
- PKCE and nonce support for security
- JWT validation using the provider's JWKS
- Cookie/session management
- Debug logging for troubleshooting

---

## Getting Started

### 1. Set Up an Identity Provider

You can use any [OAuth 2.0, OpenID Connect (OIDC) conformant provider](https://en.wikipedia.org/wiki/List_of_OAuth_providers). You will need:

- **Client ID** (and sometimes a **Client Secret**)
- The hostname of the IdP's **authorization server**
- An **OIDC Discovery document** (usually at `https://{authorization-server}/.well-known/openid-configuration`)
- A **JSON Web Key Set (JWKS)**

#### Example: Google

1. In the [Google API Console](https://console.cloud.google.com/), go to [Credentials](https://console.cloud.google.com/apis/credentials) and create an **OAuth client ID** (type: Web application).
2. Add `http://127.0.0.1:7676` and `http://127.0.0.1:7676/callback` to **Authorized JavaScript origins** and **Authorized redirect URIs** for local testing. Remove these before deploying to production!
3. Click **Create** and save:
   - The **client ID** in `.secret.client_id`
   - The **client secret** in `.secret.client_secret`
   - A random secret in `.secret.nonce_secret`:
     ```sh
     dd if=/dev/random bs=32 count=1 | base64 > .secret.nonce_secret
     ```
   - If your origin requires an API key, save it in `.secret.api_key`.
4. Fetch Google's OIDC Discovery document and JWKS, and **JSON-stringify** them for use in Fastly:
   ```sh
   curl -s https://accounts.google.com/.well-known/openid-configuration | jq -c @json
   curl -s https://www.googleapis.com/oauth2/v3/certs | jq -c @json
   ```
   - Paste the stringified discovery document into the `openid_configuration` property in `fastly.toml` under `[local_server.config_stores.oauth_config.contents]`.
   - Paste the stringified JWKS into the `jwks` property in the same section.
   - **Important:** The JWKS must be kept up to date. If you see errors about `No matching JWK found for kid ...`, update your JWKS from the IdP's `jwks_uri`.

> **Note:** All secrets and configuration must be provided via Fastly Secret Store and Config Store, even for local development. Environment variables are not used.

---

### 2. Test Locally

Start the local development server:

```sh
fastly compute serve
```

Visit [http://127.0.0.1:7676](http://127.0.0.1:7676) and complete the OAuth flow.

---

### 3. Deploy to Fastly

Build and deploy your service:

```sh
fastly compute publish
```

You'll be prompted to configure backends for your origin and IdP, and to provide secrets and config values. When finished, you'll get a Fastly-assigned domain (e.g., `random-funky-words.edgecompute.app`).

---

### 4. Link Your Fastly Domain to Your IdP

Add `https://{your-fastly-domain}/callback` to the list of allowed callback URLs in your IdP's app configuration (for Google, this is **Authorized redirect URIs**).

---

### 5. Try It Out!

Visit your Fastly-assigned domain. You should be prompted to log in with your IdP, and after authenticating, you'll see content from your origin.

---

## The Flow in Detail

1. User requests a protected resource (no session cookie).
2. The service generates a `state` and `code_verifier`, stores them in cookies, and redirects to the IdP.
3. The user authenticates with the IdP.
4. The IdP redirects back with an authorization code and state.
5. The service validates the state, exchanges the code for tokens, and sets cookies.
6. On subsequent requests, the service validates the tokens and proxies to your origin.

![Edge authentication flow diagram](https://user-images.githubusercontent.com/12828487/115379253-4438be80-a1c9-11eb-81af-9470e324434a.png)

---

## Local Development

Run `fastly compute serve --watch` to watch for changes.

### Debug Logging

Set `debug.LOG = true` in `main.go` to enable detailed debug output.

---

## Project Structure

```
compute-go-auth/
├── main.go                 # Main application entry point with all OAuth logic
├── debug/
│   └── debug.go            # Debug logging control
├── config/
│   └── config.go           # Configuration loading from Fastly stores
├── cookie/
│   └── cookie.go           # Cookie parsing and setting
├── fastly.toml             # Fastly service configuration
├── go.mod                  # Go module dependencies
├── go.sum                  # Go module checksums
├── LICENSE                 # License file
└── README.md               # This file
```

---

## Implementation Details

- Uses Go's standard library for crypto, JWT, and HTTP.
- No custom JWT or PKCE libraries—everything is standard Go.
- JWKS and OIDC config are loaded from Fastly Config Store.
- All secrets (client ID, client secret, nonce secret, API key) are loaded from Fastly Secret Store.

---

## Troubleshooting

### JWKS and Key Rotation

- If you see errors like `No matching JWK found for kid ...` or `ID token invalid`, your JWKS is likely out of date.
- **Solution:** Download the latest JWKS from your IdP's `jwks_uri` (for Google: [https://www.googleapis.com/oauth2/v3/certs](https://www.googleapis.com/oauth2/v3/certs)) and update the `jwks` key in your Fastly Config Store.
- In production and local development, JWKS is **not** fetched dynamically for security and performance. Update it manually or automate this as part of your deployment.

### Backends

- Ensure you have created the following **Backends** in your compute service configuration:
  - `idp`, pointing to `accounts.google.com:443`
  - `origin`, pointing to your origin server

---

## Issues

If you encounter any bugs or unexpected behavior, please [file an issue][bug].

[bug]: https://github.com/rguliyev/compute-go-auth/issues/new?labels=bug
