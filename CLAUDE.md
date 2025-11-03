# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

This is a **proof-of-concept demonstration** of Authorization Code + PKCE OAuth flow for client-side SPAs. It's designed to showcase how modern browser-based apps can handle OAuth securely without a backend, serving as a reference implementation and educational tool for advocating PKCE patterns in internal applications.

## Development Commands

```bash
npm start          # Run the static file server (localhost:8080)
npm run types      # Type-check JavaScript with TypeScript (JSDoc annotations)
npm run lint       # Lint code with ESLint (max-warnings: 0)
npm run lint:fix   # Auto-fix linting issues
```

## Architecture Overview

### Separation of Concerns

The codebase strictly separates **OAuth/token management** from **application logic**:

- **`src/pkce.js`**: Pure PKCE implementation
  - Static singleton class handling only the OAuth dance and token lifecycle
  - Provides `getAccessToken()` - returns the token, application decides what to do with it
  - **Does NOT** call any user APIs or handle application-specific logic
  - All internal state (`#accessToken`, `#tokenExpiry`) is private

- **`src/index.js`**: Application layer
  - Imports PKCE singleton and uses it to get tokens
  - Contains all application-specific logic (fetching user info from Auth0's UserInfo API, UI management)
  - Handles the three view states: login, loading, profile

### Single-Page Flow

The app uses **one HTML file** (`src/index.html`) with three mutually exclusive views toggled via the `hidden` attribute:
- `#login-view` - Initial state
- `#loading-view` - During OAuth callback
- `#profile-view` - After successful authentication

State detection is based on URL query parameters (`?code=...`) rather than separate routes.

### Security Model

**Critical principles** embedded in this implementation:

1. **In-memory token storage only** - tokens are never persisted to localStorage/sessionStorage (except PKCE verifier during redirect, which is single-use)
2. **Production-grade CSP** - no `'unsafe-inline'`, external stylesheets only
3. **Semantic HTML** - uses `<main>`, `hidden` attribute, `<ol>`/`<ul>` for lists
4. **No abbreviations** - all IDs/classes use full words (e.g., `login-button` not `login-btn`) for non-native English speakers

### Configuration

Auth0 credentials are configured in `src/pkce.js`. To configure for a new Auth0 tenant:

```javascript
static #config = {
  domain: 'YOUR-TENANT.us.auth0.com',
  clientId: 'YOUR-CLIENT-ID',
  // No clientSecret - Auth0 properly supports public clients
  redirectUri: 'http://localhost:8080/',
  authEndpoint: 'https://YOUR-TENANT.us.auth0.com/authorize',
  tokenEndpoint: 'https://YOUR-TENANT.us.auth0.com/oauth/token',
  userInfoEndpoint: 'https://YOUR-TENANT.us.auth0.com/userinfo',
  scopes: ['openid', 'profile', 'email'],
};
```

Also update:
- `src/index.js`: userinfo fetch URL
- `src/index.html`: CSP `connect-src` directive

Redirect URI must be registered in Auth0 Application Settings under "Allowed Callback URLs" as `http://localhost:8080/` (trailing slash).

## Code Style Preferences

**Author preference** (enforce these):
- **Kebab-case** for all HTML IDs and classes (`user-name` not `userName`)
- **Arrow functions** for all top-level module functions
- **Relative imports** with `./` prefix (e.g., `import PKCE from './pkce.js'`)
- **Lowercase HTML** where sensible (`<!doctype html>`, `charset="utf-8"`)
- **Proper typography** - use `…` (U+2026) not `...`
- **Semantic HTML** - `<main>` over `<div>`, `hidden` attribute over `.hidden` class
- **No inline styles** - always external CSS files
- **Strict CSP** - everything from origin except Auth0 API calls
- **JSDoc types** for everything - comprehensive TypeScript checking via JSDoc annotations
- **Pinned dependencies** - no `^` or `~` in package.json

## Type Checking Strategy

This project uses **TypeScript for type checking only** (no transpilation):
- JavaScript files are type-checked via JSDoc annotations
- `tsconfig.json` is configured for application code (not library)
- `noEmit: true` - no `.d.ts` files generated
- Server code (`server.js`) is excluded from type checking (Node.js environment vs. browser)
- All functions must have JSDoc with `@param` and `@returns`

## OAuth Flow Implementation

The PKCE flow is implemented across three phases:

1. **Login initiation** (`PKCE.login()`)
   - Generates cryptographically random verifier (32 bytes)
   - Creates SHA-256 challenge
   - Stores verifier in sessionStorage (temporary)
   - Redirects to Google with challenge

2. **Callback handling** (`PKCE.#handleCallback()`)
   - Detects `?code=` in URL
   - Exchanges code + verifier for access token at Google's token endpoint
   - Stores token in-memory
   - Redirects to clean URL

3. **Token usage** (application layer)
   - Calls `PKCE.getAccessToken()` to retrieve token
   - Uses token to fetch user info from Google's UserInfo API
   - Never exposed to `pkce.js` - that's application concern

## What This Demo Does NOT Include

(But would be required for production)
- DPoP (proof-of-possession tokens)
- Refresh token rotation
- Token revocation on logout
- Server-side CSP headers (only meta tag)
