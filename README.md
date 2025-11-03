# PKCE OAuth Demo

A minimal demonstration of **Authorization Code + PKCE** flow using Auth0.

This is a pure client-side implementation with no backend auth logic — just static files served by a simple Node.js server.

## Why PKCE?

**PKCE (Proof Key for Code Exchange)** lets client-side apps handle their own sign-in securely, without needing a backend or stored secrets. The flow is simple, standards-based, and works anywhere a static site can be hosted. PKCE gives developers full control over local auth behavior while keeping credentials short-lived and scoped — a clean, modern alternative to heavyweight server-side auth.

## Why Roll Our Own?

**TL;DR: No OAuth package works as drop-in ES modules in browsers without build tools.**

OAuth is a protocol specification (maintained by the IETF and OpenID Foundation), not an organization — so there's no "official OAuth package" to install. While many community and IdP-provided packages exist, virtually **all** require build tooling:

- Most assume Node.js dependencies and CommonJS
- Built for webpack/rollup/vite consumption
- Require transpilation or polyfills for browser use
- Often framework-specific (React/Angular/Vue)

This is a frustrating pattern in modern web development. Industry leaders _could_ author hyper-portable packages that work natively in browsers using ES modules, but they simply choose not to. The web platform has supported ES modules natively since 2017 — we shouldn't need build tooling for fundamental protocols like OAuth.

**What we built** (~600 lines) is essentially what these packages do under the hood: direct usage of Web Crypto API, Fetch API, and OAuth endpoints per the RFC specifications. This is leaner, more transparent, and actually _more portable_ than any third-party OAuth library.

## Security Posture

With PKCE paired with DPoP, short-lived tokens, and a strict Content Security Policy, the security posture of a modern SPA is effectively equivalent to a backend-for-frontend approach. The remaining distinction isn't about cryptographic safety — it's about whether the runtime (browser vs. server) can be centrally attested and audited. In other words, the technical risks are well-mitigated; what's left is a trust-boundary policy question, not an actual weakness in the flow.

### Security Features in This Demo

- **PKCE (RFC 7636)**: Prevents authorization code interception attacks
- **In-memory token storage**: Tokens never touch localStorage/sessionStorage (except PKCE verifier during redirect)
- **Short-lived access tokens**: Default ~1 hour expiry from Google
- **State parameter**: CSRF protection during OAuth redirect
- **No client secrets**: Public client pattern (safe for browser)
- **Strict CSP**: Production-grade Content Security Policy with no `unsafe-inline` or `unsafe-eval`

### What's Not Included (But Should Be in Production)

- **DPoP (RFC 9449)**: Sender-constrained tokens for proof-of-possession
- **Refresh token rotation**: With reuse detection (OAuth 2.1 guidance)
- **Token revocation**: On logout, call IdP revocation endpoint

## Setup

### 1. Create an Auth0 Application

1. Sign up for [Auth0](https://auth0.com/signup) (free tier available)
2. Go to **Applications** > **Applications** in the dashboard
3. Click **Create Application**
4. Configure:
   - Name: "PKCE POC" (or whatever you prefer)
   - Application Type: **Single Page Application** (this is key!)
   - Click **Create**
5. In the **Settings** tab:
   - **Allowed Callback URLs**:
     ```
     http://localhost:8080/,
     https://theengineear.github.io/poc-pkce/src/index.html,
     https://esm.sh/gh/theengineear/poc-pkce@{COMMIT_HASH}/src/index.html?raw
     ```
   - **Allowed Logout URLs**:
     ```
     http://localhost:8080/,
     https://theengineear.github.io/poc-pkce/src/index.html,
     https://esm.sh/gh/theengineear/poc-pkce@{COMMIT_HASH}/src/index.html?raw
     ```
   - **Allowed Web Origins**:
     ```
     http://localhost:8080,
     https://theengineear.github.io,
     https://esm.sh
     ```
   - Click **Save Changes**
6. Note your **Domain** and **Client ID** (no Client Secret needed!)

### 2. Configure the App

Open `src/pkce.js` and update the `#config` object:

```javascript
static #config = {
  domain: 'YOUR-TENANT.us.auth0.com', // Replace with your Auth0 domain
  clientId: 'YOUR-CLIENT-ID', // Replace with your Client ID
  // No clientSecret needed! Auth0 properly supports public clients
  redirectUri: 'http://localhost:8080/',
  authEndpoint: 'https://YOUR-TENANT.us.auth0.com/authorize',
  tokenEndpoint: 'https://YOUR-TENANT.us.auth0.com/oauth/token',
  userInfoEndpoint: 'https://YOUR-TENANT.us.auth0.com/userinfo',
  scopes: ['openid', 'profile', 'email'],
};
```

Also update the userinfo endpoint in `src/index.js`:
```javascript
const response = await fetch('https://YOUR-TENANT.us.auth0.com/userinfo', {
  headers: { 'Authorization': `Bearer ${accessToken}` },
});
```

And the CSP in `src/index.html`:
```html
<meta
  http-equiv="Content-Security-Policy"
  content="
    default-src 'self';
    connect-src 'self' https://YOUR-TENANT.us.auth0.com;
  ">
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Run the Server

```bash
npm start
```

Or with Node directly:

```bash
node server.js
```

### 5. Open in Browser

Navigate to [http://localhost:8080](http://localhost:8080)

Click "Sign in with Google" and follow the OAuth flow.

## What Happens Under the Hood

### Step 1: User Clicks "Sign In"

1. Generate random PKCE **code verifier** (43-128 chars, cryptographically random)
2. Hash verifier with SHA-256 to create **code challenge**
3. Store verifier in sessionStorage (temporary, single-use)
4. Redirect to Google with:
   - `response_type=code` (Authorization Code flow)
   - `code_challenge` (hashed verifier)
   - `code_challenge_method=S256`
   - `state` (CSRF token)

### Step 2: User Authorizes at Auth0

- Auth0 shows login/consent screen
- User authenticates and approves requested scopes
- Auth0 redirects back to `/` with **authorization code** in query params

### Step 3: Exchange Code for Token

1. Extract `code` from URL
2. Retrieve stored `verifier` from sessionStorage
3. POST to Auth0's token endpoint with:
   - `code` (from URL)
   - `code_verifier` (proves we initiated the flow)
4. Auth0 validates that `hash(verifier) === challenge` from step 1
5. If valid, Auth0 returns access token
6. Store token **in-memory only**
7. Fetch user profile from UserInfo endpoint

### Step 4: Display Profile

- Show user's name and email
- Access token stored in-memory (cleared on page reload)
- Refresh token stored in localStorage (enables silent re-auth)

## Why No Backend?

This demonstrates the **portable** advantage of PKCE SPAs:

- Runs from any static host (CDN, S3, GitHub Pages, localhost)
- No server-side session management
- No secrets to manage or rotate
- Faster local development (no auth wall when prototyping)

The included `server.js` is **just a static file server** — it performs zero auth logic. You could swap it for Python's `http.server`, nginx, or any CDN.

## Portability Demo

This app uses **dynamic redirect URIs** - it auto-detects the current origin and works from anywhere.

**Live Demo URLs:**
- **Localhost**: http://localhost:8080/
- **GitHub Pages**: https://theengineear.github.io/poc-pkce/src/index.html
- **esm.sh CDN**: https://esm.sh/gh/theengineear/poc-pkce@{COMMIT_HASH}/src/index.html?raw (replace `{COMMIT_HASH}` with actual hash after pushing)

The exact same HTML file authenticates users from any origin. Just add the URL to Auth0's allowed callbacks.

**How it works:**
```javascript
// In pkce.js - auto-detects current URL
redirectUri: window.location.origin + window.location.pathname
```

This proves PKCE's true portability - no backend configuration needed, just update the OAuth provider's allow list.

## Project Structure

```
poc-pkce/
├── server.js              # Simple Node.js static file server (no auth logic)
├── package.json           # npm scripts and dependencies
├── tsconfig.json          # TypeScript configuration for JSDoc type checking
├── eslint.config.js       # ESLint configuration
├── src/
│   ├── index.html         # Single page (handles login, callback, and profile)
│   ├── index.css          # Styles (external stylesheet for strict CSP)
│   ├── index.js           # Application layer: UI management and user info fetching
│   └── pkce.js            # PKCE layer: OAuth flow and token lifecycle only
├── CLAUDE.md              # Documentation for AI assistants
└── README.md
```

### Separation of Concerns

- **`pkce.js`**: Handles only the OAuth authorization dance and token lifecycle. Provides `getAccessToken()` for the application to use. Does NOT fetch user info or make API calls.
- **`index.js`**: Application layer. Uses the token from PKCE to fetch user info and manage UI state.

## Common Questions

### Q: Is it safe to do OAuth in the browser?

**A:** With PKCE, yes. PKCE was designed specifically for public clients (SPAs, mobile apps) that can't store secrets. The code verifier acts as a dynamic, per-request secret that never leaves your origin.

### Q: What if someone steals the authorization code?

**A:** They can't use it. The OAuth provider requires the original `code_verifier` to exchange the code for a token. The attacker only sees the `code_challenge` (a hash), not the verifier.

### Q: Why not use Implicit Flow?

**A:** Implicit flow is deprecated (OAuth 2.1). It puts tokens in URL fragments, which are more easily leaked. Authorization Code + PKCE is the modern standard.

### Q: What about refresh tokens?

**A:** This demo doesn't use them for simplicity. In production, use rotating refresh tokens with reuse detection, or DPoP-bound refresh tokens (OAuth 2.1 guidance).

### Q: Isn't localStorage safer than in-memory?

**A:** No — localStorage persists across sessions and is accessible to any script on your origin (XSS risk). In-memory tokens disappear on page reload, reducing attack surface.

## Development Commands

```bash
# Start the development server
npm start

# Run type checking (TypeScript + JSDoc)
npm run types

# Run linting
npm run lint

# Run linting with auto-fix
npm run lint:fix
```

## Production Considerations

Before deploying this pattern for real apps:

1. **Add DPoP** for sender-constrained tokens (RFC 9449)
2. **Implement refresh token rotation** with reuse detection
3. **Serve CSP via HTTP headers** (not just meta tags)
4. **Use narrow scopes** (principle of least privilege)
5. **Separate client IDs per environment** (dev/staging/prod)
6. **Monitor IdP logs** for unusual token issuance patterns
7. **Token revocation on logout** (call Google's revocation endpoint)
8. **Consider a BFF pattern** if handling regulated data (HIPAA, PCI, SOX)

## References

- [RFC 7636: PKCE](https://datatracker.ietf.org/doc/html/rfc7636) — The PKCE spec
- [OAuth 2.1 Draft](https://oauth.net/2.1/) — Modern OAuth guidance (mandates PKCE)
- [RFC 9449: DPoP](https://datatracker.ietf.org/doc/html/rfc9449) — Proof-of-possession for tokens
- [IETF Browser-Based Apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps) — Best practices for SPAs
