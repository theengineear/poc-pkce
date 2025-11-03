/**
 * PKCE OAuth Flow Implementation
 *
 * This demonstrates Authorization Code + PKCE for a public client (SPA).
 *
 * Security philosophy (from our internal discussion):
 * - PKCE prevents code interception attacks (RFC 7636)
 * - In-memory token storage (never localStorage/sessionStorage)
 * - Short-lived access tokens
 * - No client secrets (public client pattern)
 *
 * The gap between this and a BFF is organizational, not cryptographic:
 * with PKCE + DPoP (future), short-lived tokens, and strict CSP,
 * the security posture is effectively equivalent. The remaining distinction
 * is about trust-boundary attestability (browser vs. server runtime),
 * not about fundamental security.
 */

/**
 * @typedef {Object} AuthState
 * @property {'callback' | 'authenticated' | 'unauthenticated'} state - Current authentication state
 */

/**
 * PKCE - Proof Key for Code Exchange OAuth flow handler
 *
 * A static singleton that manages OAuth authentication using PKCE.
 * All methods are static and the class maintains in-memory token state.
 *
 * Usage:
 *   import PKCE from './pkce-module.js';
 *
 *   await PKCE.configure({
 *     issuer: 'dev-c6d0wummlck4y50j.us.auth0.com',
 *     clientId: 'Kvl9KjlEK6rWxRyrUf1npDpxYURvS9vS',
 *     scopes: ['openid', 'profile', 'email', 'offline_access'],
 *   });
 *
 *   await PKCE.initialize();
 */
class PKCE {
  // Configuration - set via configure() method
  static #config = null;
  static #OIDC_CACHE_KEY_PREFIX = 'pkce_oidc_config_';
  static #OIDC_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Token storage strategy
   *
   * Access tokens (short-lived):
   * - Stored in-memory only
   * - Cleared on page reload/close
   * - Not accessible via XSS-injected scripts after page reload
   *
   * Refresh tokens (long-lived):
   * - Stored in localStorage for session persistence
   * - Allows silent re-authentication on page reload/new tabs
   * - Should use rotation (single-use tokens) for security
   *
   * This hybrid approach balances security and UX:
   * - Access tokens expire quickly (typically 1 hour)
   * - Refresh tokens enable seamless user experience
   * - XSS attacks have limited window to steal access tokens
   *
   * @type {string | null}
   */
  static #accessToken = null;

  /**
   * @type {number | null}
   */
  static #tokenExpiry = null;

  /**
   * Timer ID for automatic token refresh
   * @type {number | null}
   */
  static #refreshTimer = null;

  /**
   * LocalStorage keys for refresh token persistence
   */
  static #REFRESH_TOKEN_KEY = 'pkce_refresh_token';

  /**
   * Track if storage event listener is set up
   */
  static #storageListenerActive = false;

  // Private helper methods

  /**
   * Ensure PKCE has been configured
   * @throws {Error} If configure() hasn't been called
   */
  static #ensureConfigured() {
    if (!this.#config) {
      throw new Error('PKCE not configured. Call PKCE.configure() first.');
    }
  }

  /**
   * Set up storage event listener for multi-tab token synchronization
   * When another tab refreshes tokens, this tab syncs automatically
   */
  static #setupStorageListener() {
    if (this.#storageListenerActive) {
      return; // Already set up
    }

    window.addEventListener('storage', async (e) => {
      // Check if another tab updated the refresh token
      if (e.key === this.#REFRESH_TOKEN_KEY && e.newValue && e.newValue !== e.oldValue) {
        console.log('Token refresh detected in another tab - syncing...');

        // Another tab refreshed - cancel our scheduled refresh
        if (this.#refreshTimer) {
          clearTimeout(this.#refreshTimer);
          this.#refreshTimer = null;
        }

        // Refresh our access token to stay in sync
        try {
          await this.#refreshAccessToken();
        } catch (error) {
          console.error('Failed to sync token from another tab:', error);
        }
      }
    });

    this.#storageListenerActive = true;
  }

  /**
   * Schedule automatic token refresh 5 minutes before expiry
   * Clears any existing refresh timer first
   */
  static #scheduleTokenRefresh() {
    // Clear any existing timer
    if (this.#refreshTimer) {
      clearTimeout(this.#refreshTimer);
      this.#refreshTimer = null;
    }

    if (!this.#tokenExpiry) {
      return;
    }

    // Calculate milliseconds until 5 minutes before expiry
    const now = Date.now();
    const fiveMinutesMs = 5 * 60 * 1000;
    const refreshAt = this.#tokenExpiry - fiveMinutesMs;
    const delay = refreshAt - now;

    // Only schedule if we have at least 1 minute before we need to refresh
    if (delay > 60 * 1000) {
      this.#refreshTimer = setTimeout(async () => {
        try {
          await this.#refreshAccessToken();
        } catch (error) {
          console.error('Automatic token refresh failed:', error);
        }
      }, delay);
    }
  }

  /**
   * Fetch OIDC Discovery configuration with localStorage caching
   * @param {string} issuer - OIDC issuer domain
   * @returns {Promise<any>} OIDC configuration object
   */
  static async #fetchOIDCConfiguration(issuer) {
    const cacheKey = `${this.#OIDC_CACHE_KEY_PREFIX}${issuer}`;

    // Check cache first
    const cached = localStorage.getItem(cacheKey);
    if (cached) {
      try {
        const { data, timestamp } = JSON.parse(cached);
        if (Date.now() - timestamp < this.#OIDC_CACHE_TTL) {
          return data;
        }
      } catch (_) {
        // Invalid cache, continue to fetch
      }
    }

    // Fetch from .well-known endpoint
    const discoveryUrl = `https://${issuer}/.well-known/openid-configuration`;
    const response = await fetch(discoveryUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch OIDC configuration from ${discoveryUrl}`);
    }

    const data = await response.json();

    // Cache the result
    localStorage.setItem(cacheKey, JSON.stringify({
      data,
      timestamp: Date.now(),
    }));

    return data;
  }

  /**
   * Generate a cryptographically random PKCE code verifier
   *
   * Spec: 43-128 character string using [A-Z][a-z][0-9]-._~
   * (RFC 7636 Section 4.1)
   */
  static #generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return this.#base64URLEncode(array);
  }

  /**
   * Generate the PKCE code challenge from the verifier
   *
   * Method: S256 (SHA-256 hash, then base64url encode)
   * This is the recommended method; plain is only for legacy clients.
   * (RFC 7636 Section 4.2)
   * @param {string} verifier - The code verifier string
   * @returns {Promise<string>} Base64URL encoded SHA-256 hash
   */
  static async #generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return this.#base64URLEncode(new Uint8Array(hash));
  }

  /**
   * Base64-URL encoding (without padding)
   * Standard base64 but with URL-safe characters and no padding
   * @param {Uint8Array} buffer - Binary data to encode
   * @returns {string} Base64URL encoded string
   */
  static #base64URLEncode(buffer) {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, ''); // Remove padding
  }

  /**
   * Handle the OAuth callback
   *
   * This is step 2 of PKCE:
   * 1. Extract authorization code from URL
   * 2. Retrieve our stored verifier
   * 3. Exchange code + verifier for access token
   * 4. Clear temporary storage and store token in-memory
   *
   * Why this is secure without a backend:
   * - The code is single-use and expires quickly (~10 min)
   * - Without the verifier, the code is useless (PKCE protection)
   * - The verifier never left our origin (sessionStorage is origin-bound)
   * - Google validates the verifier hash against the challenge we sent
   */
  static async #handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');

    // Retrieve stored values
    const verifier = sessionStorage.getItem('pkce_verifier');
    const storedCsrfToken = sessionStorage.getItem('oauth_state');

    // Clear temporary storage immediately
    sessionStorage.removeItem('pkce_verifier');
    sessionStorage.removeItem('oauth_state');

    // Validate
    if (error) {
      alert(`OAuth error: ${error}`);
      window.location.href = '/';
      return;
    }

    if (!code || !verifier) {
      alert('Missing code or verifier');
      window.location.href = '/';
      return;
    }

    // Parse state parameter: {csrf_token}|{return_url}
    const [receivedCsrfToken, returnUrl] = state ? state.split('|', 2) : [null, null];

    // Validate CSRF token (state parameter)
    if (receivedCsrfToken !== storedCsrfToken) {
      alert('State mismatch - possible CSRF attack');
      window.location.href = '/';
      return;
    }

    // Exchange authorization code for access token
    try {
      const tokenResponse = await fetch(this.#config.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: this.#config.clientId,
          code: code,
          code_verifier: verifier, // This proves we initiated the flow
          grant_type: 'authorization_code',
          redirect_uri: this.#config.redirectUri,
        }),
      });

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json();
        throw new Error(`Token exchange failed: ${errorData.error_description || errorData.error}`);
      }

      const tokenData = await tokenResponse.json();

      // Store access token in-memory only
      this.#accessToken = tokenData.access_token;
      this.#tokenExpiry = Date.now() + (tokenData.expires_in * 1000);

      // Schedule automatic refresh before expiry
      this.#scheduleTokenRefresh();

      // Store refresh token in localStorage (if provided)
      if (tokenData.refresh_token) {
        localStorage.setItem(this.#REFRESH_TOKEN_KEY, tokenData.refresh_token);
      }

      // Redirect to original URL (deep linking support) or clean up callback URL
      if (returnUrl) {
        // Use replaceState to avoid creating history entries for OAuth callback
        window.history.replaceState({}, document.title, returnUrl);
      } else {
        // Fallback: just clean up the callback URL
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    } catch (error) {
      console.error('Token exchange error:', error);
      const message = error instanceof Error ? error.message : 'Unknown error';
      alert(`Authentication failed: ${message}`);
      window.location.href = '/';
    }
  }

  /**
   * Refresh the access token using a stored refresh token
   *
   * This method uses the OAuth 2.0 refresh token grant to obtain a new
   * access token without requiring user interaction. This is NOT part of PKCE -
   * it's a separate OAuth grant type.
   *
   * If Auth0 is configured with refresh token rotation, the old refresh token
   * will be invalidated and a new one will be returned.
   *
   * @returns {Promise<boolean>} True if refresh succeeded, false otherwise
   */
  static async #refreshAccessToken() {
    const refreshToken = localStorage.getItem(this.#REFRESH_TOKEN_KEY);
    if (!refreshToken) {
      return false;
    }

    try {
      const tokenResponse = await fetch(this.#config.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: this.#config.clientId,
          refresh_token: refreshToken,
        }),
      });

      if (!tokenResponse.ok) {
        // Refresh token is invalid or expired - clear it
        localStorage.removeItem(this.#REFRESH_TOKEN_KEY);
        return false;
      }

      const tokenData = await tokenResponse.json();

      // Store new access token in-memory
      this.#accessToken = tokenData.access_token;
      this.#tokenExpiry = Date.now() + (tokenData.expires_in * 1000);

      // Schedule automatic refresh before expiry
      this.#scheduleTokenRefresh();

      // If rotation is enabled, Auth0 returns a new refresh token
      if (tokenData.refresh_token) {
        localStorage.setItem(this.#REFRESH_TOKEN_KEY, tokenData.refresh_token);
      }

      return true;
    } catch (error) {
      console.error('Token refresh error:', error);
      localStorage.removeItem(this.#REFRESH_TOKEN_KEY);
      return false;
    }
  }

  // Public API

  /**
   * Configure PKCE with issuer, client ID, and scopes
   * Uses OIDC Discovery to fetch endpoints automatically
   *
   * @param {Object} options - Configuration options
   * @param {string} options.issuer - OIDC issuer (e.g., 'dev-xxx.us.auth0.com')
   * @param {string} options.clientId - OAuth client ID
   * @param {string[]} options.scopes - OAuth scopes (e.g., ['openid', 'profile', 'email'])
   * @returns {Promise<void>}
   */
  static async configure({ issuer, clientId, scopes }) {
    if (!issuer || !clientId || !scopes) {
      throw new Error('PKCE.configure: issuer, clientId, and scopes are required');
    }

    // Fetch endpoints from OIDC Discovery
    const oidcConfig = await this.#fetchOIDCConfiguration(issuer);

    this.#config = {
      issuer,
      clientId,
      authorizationEndpoint: oidcConfig.authorization_endpoint,
      tokenEndpoint: oidcConfig.token_endpoint,
      userinfoEndpoint: oidcConfig.userinfo_endpoint,
      scopes,
      redirectUri: window.location.origin + window.location.pathname,
    };
  }

  /**
   * Initiate the OAuth authorization flow
   *
   * This is step 1 of PKCE:
   * 1. Generate verifier (random secret we keep)
   * 2. Generate challenge (hashed verifier we send)
   * 3. Store verifier in sessionStorage temporarily (only place we use it)
   * 4. Redirect user to Google's authorization page with challenge
   *
   * Security: The challenge is public; only the verifier is secret.
   * Even if an attacker intercepts the authorization code, they can't
   * exchange it without the verifier (which never left our origin).
   */
  static async login() {
    this.#ensureConfigured();

    // Generate PKCE parameters
    const verifier = this.#generateCodeVerifier();
    const challenge = await this.#generateCodeChallenge(verifier);

    // Store verifier temporarily for the callback
    // (sessionStorage is acceptable here since it's single-use and short-lived)
    sessionStorage.setItem('pkce_verifier', verifier);

    // Build state parameter: combines CSRF token + return URL for deep linking
    // Format: {csrf_token}|{return_url}
    const csrfToken = this.#generateCodeVerifier();
    const returnUrl = window.location.href;
    const state = `${csrfToken}|${returnUrl}`;

    // Build authorization URL
    const params = new URLSearchParams({
      client_id: this.#config.clientId,
      redirect_uri: this.#config.redirectUri,
      response_type: 'code', // Authorization Code flow (not implicit!)
      scope: this.#config.scopes.join(' '),
      code_challenge: challenge,
      code_challenge_method: 'S256', // SHA-256 (required for security)
      state: state, // CSRF protection + return URL
    });

    // Store CSRF token for validation
    sessionStorage.setItem('oauth_state', csrfToken);

    // Redirect to Auth0
    window.location.href = `${this.#config.authorizationEndpoint}?${params}`;
  }

  /**
   * Logout: clear tokens and state
   *
   * Clears both in-memory access token and localStorage refresh token.
   *
   * In production, you'd also:
   * - Revoke the refresh token at the IdP
   * - Call Auth0's revocation endpoint
   * - Clear any additional app state
   */
  static logout() {
    // Clear tokens
    this.#accessToken = null;
    this.#tokenExpiry = null;
    localStorage.removeItem(this.#REFRESH_TOKEN_KEY);

    // Clear automatic refresh timer
    if (this.#refreshTimer) {
      clearTimeout(this.#refreshTimer);
      this.#refreshTimer = null;
    }

    // Reload current page (not domain root) to show login view
    window.location.href = window.location.pathname + window.location.search + window.location.hash;
  }

  /**
   * Get the current access token
   *
   * Returns null if not authenticated or token is expired.
   * @returns {string | null} The access token or null
   */
  static getAccessToken() {
    if (!this.#accessToken || !this.#tokenExpiry || Date.now() >= this.#tokenExpiry) {
      return null;
    }
    return this.#accessToken;
  }

  /**
   * Check if user is currently authenticated
   * @returns {boolean} True if authenticated with valid token
   */
  static isAuthenticated() {
    return this.#accessToken !== null && this.#tokenExpiry !== null && Date.now() < this.#tokenExpiry;
  }

  /**
   * Initialize the PKCE flow
   *
   * Detects OAuth callback and handles token exchange, or checks for existing auth.
   * On page load, attempts to refresh access token using stored refresh token.
   * Returns the current authentication state.
   * @returns {Promise<AuthState>} Current authentication state
   */
  static async initialize() {
    this.#ensureConfigured();

    // Set up storage listener for multi-tab synchronization
    this.#setupStorageListener();

    // Check if we have an authorization code in the URL (OAuth callback)
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');

    if (code) {
      // We're in the OAuth callback flow
      await this.#handleCallback();
      return { state: 'callback' };
    }

    // Check if we have a valid token in memory
    if (this.isAuthenticated()) {
      return { state: 'authenticated' };
    }

    // No token in memory - try to refresh using stored refresh token
    const refreshed = await this.#refreshAccessToken();
    if (refreshed) {
      return { state: 'authenticated' };
    }

    return { state: 'unauthenticated' };
  }
}

// Auto-configuration from pkce.json (if it exists)
// This runs at module load time. If pkce.json exists at document root,
// we auto-configure and enforce authentication. Otherwise, the module
// must be manually configured via PKCE.configure().
try {
  const configUrl = new URL('./pkce.json', document.baseURI);
  const response = await fetch(configUrl);

  if (response.ok) {
    const config = await response.json();
    await PKCE.configure(config);

    const state = await PKCE.initialize();

    // If unauthenticated, redirect to login (authentication enforcement)
    if (state.state === 'unauthenticated') {
      await PKCE.login();
    }
  }
} catch (error) {
  // pkce.json not found or invalid - manual configuration required
  // This is expected for applications that configure programmatically
}

// Export as default
export default PKCE;
