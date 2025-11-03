import PKCE from '../../pkce.js';

/**
 * Application initialization and UI management
 */

/**
 * @typedef {Object} UserInfo
 * @property {string} name - Full name of the user
 * @property {string} email - Email address
 */

// UI Helper Functions

/**
 * Show a specific view and hide all others
 * @param {string} viewId - The ID of the view to show
 * @returns {void}
 */
const showView = (viewId) => {
  ['login-view', 'profile-view', 'loading-view'].forEach(id => {
    const element = document.getElementById(id);
    if (element) element.hidden = true;
  });
  const viewElement = document.getElementById(viewId);
  if (viewElement) viewElement.hidden = false;
};

/**
 * Fetch user information from Auth0's UserInfo API
 * @param {string} accessToken - OAuth access token
 * @returns {Promise<UserInfo>} User profile information
 */
const fetchUserInfo = async (accessToken) => {
  const response = await fetch('https://dev-c6d0wummlck4y50j.us.auth0.com/userinfo', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch user info');
  }

  return response.json();
};

/**
 * Load and display the user profile
 * @returns {Promise<void>}
 */
const showProfile = async () => {
  try {
    const accessToken = PKCE.getAccessToken();
    if (!accessToken) {
      showView('login-view');
      return;
    }

    const userInfo = await fetchUserInfo(accessToken);

    // Display profile
    const nameElement = document.getElementById('user-name');

    // Extract first name from full name
    const firstName = userInfo.name ? userInfo.name.split(' ')[0] : 'there';

    if (nameElement) nameElement.textContent = firstName;

    showView('profile-view');
  } catch (error) {
    console.error('Failed to load user info:', error);
    showView('login-view');
  }
};

/**
 * Initialize the application and handle authentication state
 * @returns {Promise<void>}
 */
const initializeApp = async () => {
  // Configure PKCE with OIDC Discovery
  await PKCE.configure({
    issuer: 'dev-c6d0wummlck4y50j.us.auth0.com',
    clientId: 'Kvl9KjlEK6rWxRyrUf1npDpxYURvS9vS',
    scopes: ['openid', 'profile', 'email', 'offline_access'],
  });

  const authState = await PKCE.initialize();

  switch (authState.state) {
    case 'callback':
      // Callback completed successfully, URL cleaned up without reload
      // Check if authenticated and show profile
      if (PKCE.isAuthenticated()) {
        await showProfile();
      } else {
        showView('login-view');
      }
      break;

    case 'authenticated':
      await showProfile();
      break;

    case 'unauthenticated':
      showView('login-view');
      break;
  }

  // Attach event listeners
  document.getElementById('login-button')?.addEventListener('click', () => PKCE.login());
  document.getElementById('logout-button')?.addEventListener('click', () => PKCE.logout());
};

// Initialize on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeApp);
} else {
  initializeApp();
}
