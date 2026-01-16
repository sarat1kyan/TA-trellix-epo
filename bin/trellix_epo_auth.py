#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Trellix ePO Authentication Module
Handles secure authentication with Trellix ePO REST API
Supports token-based and basic authentication
"""

import sys
import os
import base64
import logging
import json
import time

# Add Splunk's Python library paths
SPLUNK_HOME = os.environ.get('SPLUNK_HOME', '/opt/splunk')

# Core Splunk Python paths (for requests, urllib3, etc.)
splunk_lib_paths = [
    os.path.join(SPLUNK_HOME, 'lib', 'python3.9', 'site-packages'),
    os.path.join(SPLUNK_HOME, 'lib', 'python3.7', 'site-packages'),
]
for lib_path in splunk_lib_paths:
    if os.path.isdir(lib_path) and lib_path not in sys.path:
        sys.path.insert(0, lib_path)

# Add bin directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# splunklib is not bundled with Splunk core - look for it in apps that include it
splunklib_search_paths = [
    os.path.join(os.path.dirname(__file__), '..', 'lib'),  # Our own lib folder
    os.path.join(SPLUNK_HOME, 'etc', 'apps', 'splunk_rapid_diag', 'bin'),
    os.path.join(SPLUNK_HOME, 'etc', 'apps', 'Splunk_SA_Scientific_Python_linux_x86_64', 'lib'),
    os.path.join(SPLUNK_HOME, 'etc', 'apps', 'splunk_secure_gateway', 'lib'),
    os.path.join(SPLUNK_HOME, 'etc', 'apps', 'Splunk_TA_paloalto_networks', 'lib'),
    os.path.join(SPLUNK_HOME, 'etc', 'apps', 'splunk-rolling-upgrade', 'lib'),
    os.path.join(SPLUNK_HOME, 'etc', 'apps', 'missioncontrol', 'lib'),
]

for lib_path in splunklib_search_paths:
    abs_path = os.path.abspath(lib_path)
    if os.path.isdir(abs_path) and abs_path not in sys.path:
        if os.path.isdir(os.path.join(abs_path, 'splunklib')):
            sys.path.insert(0, abs_path)
            break

# Try to import Splunk libraries - they may not be available in all contexts
try:
    from splunk.clilib.bundle_paths import make_splunkhome_path
    SPLUNK_PATHS_AVAILABLE = True
except ImportError:
    SPLUNK_PATHS_AVAILABLE = False

try:
    from splunklib import client as splunk_client
    SPLUNKLIB_AVAILABLE = True
except ImportError:
    splunk_client = None
    SPLUNKLIB_AVAILABLE = False

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


class TrellixEPOAuthError(Exception):
    """Custom exception for authentication errors"""
    pass


class TrellixEPOAuth:
    """
    Handles authentication with Trellix ePO REST API
    Supports both token-based and basic authentication
    """
    
    def __init__(self, epo_url, port=8443, username=None, password=None, 
                 token=None, ssl_verify=True, proxy_settings=None):
        """
        Initialize authentication handler
        
        Args:
            epo_url: ePO server URL (without protocol)
            port: ePO server port (default 8443)
            username: ePO username (for basic auth or token generation)
            password: ePO password (for basic auth or token generation)
            token: Pre-existing ePO token (optional)
            ssl_verify: Whether to verify SSL certificates
            proxy_settings: Dictionary with proxy settings (optional)
        """
        self.epo_url = epo_url.rstrip('/')
        self.port = port
        self.username = username
        self.password = password
        self.token = token
        self.ssl_verify = ssl_verify
        self.proxy_settings = proxy_settings or {}
        
        # Build base URL
        protocol = 'https' if port in [8443, 443] else 'http'
        self.base_url = f"{protocol}://{self.epo_url}:{self.port}/remote"
        
        # Session for connection pooling
        self.session = self._create_session()
        
        # Token cache
        self.token_expiry = None
        self.token_cache = None
        
    def _create_session(self):
        """Create requests session with retry strategy"""
        session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # SSL verification
        session.verify = self.ssl_verify
        
        # Proxy configuration
        if self.proxy_settings:
            proxies = {
                'http': self.proxy_settings.get('http_proxy'),
                'https': self.proxy_settings.get('https_proxy')
            }
            session.proxies.update({k: v for k, v in proxies.items() if v})
        
        return session
    
    def _get_stored_credentials(self, session_key, username):
        """
        Retrieve stored credentials from Splunk's encrypted storage
        
        Args:
            session_key: Splunk session key
            username: Username to retrieve credentials for
            
        Returns:
            Tuple of (username, password) or (None, None) if not found
        """
        if not SPLUNKLIB_AVAILABLE or not splunk_client:
            logger.debug("splunklib not available, cannot retrieve stored credentials")
            return (None, None)
            
        if not session_key:
            logger.debug("No session key provided, cannot retrieve stored credentials")
            return (None, None)
            
        try:
            # Create Splunk service instance
            service = splunk_client.connect(token=session_key, app='TA-trellix-epo')
            
            # Try to get stored credentials
            storage_passwords = service.storage_passwords
            
            for password in storage_passwords:
                if password.content.get('username') == username:
                    clear_password = password.content.get('clear_password')
                    return (username, clear_password)
                    
        except Exception as e:
            logger.warning(f"Could not retrieve stored credentials: {str(e)}")
            
        return (None, None)
    
    def _store_credentials(self, session_key, username, password):
        """
        Store credentials in Splunk's encrypted storage
        
        Args:
            session_key: Splunk session key
            username: Username to store
            password: Password to store (will be encrypted)
        """
        if not SPLUNKLIB_AVAILABLE or not splunk_client:
            raise TrellixEPOAuthError("splunklib not available - cannot store credentials")
            
        if not session_key:
            raise TrellixEPOAuthError("No session key provided - cannot store credentials")
            
        try:
            service = splunk_client.connect(token=session_key, app='TA-trellix-epo')
            storage_passwords = service.storage_passwords
            
            # Check if credential already exists
            for password_obj in storage_passwords:
                if password_obj.content.get('username') == username:
                    # Update existing
                    password_obj.update(password=password)
                    return
            
            # Create new credential
            storage_passwords.create(password, username)
            
        except Exception as e:
            logger.error(f"Could not store credentials: {str(e)}")
            raise TrellixEPOAuthError(f"Failed to store credentials: {str(e)}")
    
    def authenticate(self, session_key=None):
        """
        Authenticate with ePO - validates credentials work
        
        Note: Trellix ePO uses Basic Auth for all requests.
        This method validates credentials and optionally gets a token,
        but the token is not required for API access.
        
        Args:
            session_key: Splunk session key (optional, for credential storage)
            
        Returns:
            True if authentication successful
            
        Raises:
            TrellixEPOAuthError: If authentication fails
        """
        # Retrieve credentials if session_key provided
        if session_key and self.username:
            stored_user, stored_pass = self._get_stored_credentials(session_key, self.username)
            if stored_user and stored_pass:
                self.username = stored_user
                self.password = stored_pass
        
        # Validate credentials
        if not self.username or not self.password:
            raise TrellixEPOAuthError("Username and password are required for authentication")
        
        # Test authentication with a simple API call
        try:
            # Use basic auth directly - this is what ePO expects
            auth = HTTPBasicAuth(self.username, self.password)
            
            # Test with core.help - simple and always available
            test_url = f"{self.base_url}/core.help"
            
            response = self.session.get(
                test_url,
                auth=auth,
                timeout=30
            )
            
            response.raise_for_status()
            
            # If we get here, auth works
            if response.text and response.text.startswith('OK:'):
                logger.info("Successfully authenticated with ePO")
                self.token = "basic_auth"  # Mark as authenticated
                return True
            elif response.status_code == 200:
                logger.info("Successfully authenticated with ePO")
                self.token = "basic_auth"
                return True
            else:
                raise TrellixEPOAuthError("Unexpected response from ePO")
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Authentication request failed: {str(e)}"
            logger.error(error_msg)
            raise TrellixEPOAuthError(error_msg)
    
    def _is_token_valid(self):
        """Check if cached token is still valid"""
        if not self.token or not self.token_expiry:
            return False
        
        # Check if token hasn't expired (with 5 minute buffer)
        if time.time() >= (self.token_expiry - 300):
            return False
        
        return True
    
    def get_auth_headers(self, token=None):
        """
        Get authentication headers for API requests
        
        Trellix ePO uses Basic Auth with username:password for all requests.
        The token from core.authenticate is optional - direct basic auth works.
        
        Args:
            token: Authentication token (optional, not typically used)
            
        Returns:
            Dictionary with authentication headers
        """
        # Use basic auth with username:password for all requests
        # This is what works with Trellix ePO API
        if self.username and self.password:
            credentials = f"{self.username}:{self.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {
                'Authorization': f'Basic {encoded}',
                'Content-Type': 'application/json'
            }
        elif token or self.token:
            # Fallback to token-based if no password
            auth_token = token or self.token
            return {
                'Authorization': f'Basic {base64.b64encode(f"{auth_token}:".encode()).decode()}',
                'Content-Type': 'application/json'
            }
        else:
            raise TrellixEPOAuthError("No authentication credentials available")
    
    def test_connection(self, session_key=None):
        """
        Test connection to ePO server
        
        Args:
            session_key: Splunk session key (optional)
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            token = self.authenticate(session_key)
            if token:
                return (True, "Connection successful")
            else:
                return (False, "Authentication failed - no token received")
        except TrellixEPOAuthError as e:
            return (False, f"Authentication failed: {str(e)}")
        except Exception as e:
            return (False, f"Connection test failed: {str(e)}")


if __name__ == "__main__":
    # Test authentication
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: trellix_epo_auth.py <epo_url> <username> <password> [port]")
        sys.exit(1)
    
    epo_url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 8443
    
    auth = TrellixEPOAuth(epo_url, port, username, password)
    
    try:
        token = auth.authenticate()
        print(f"Authentication successful. Token: {token[:20]}...")
    except TrellixEPOAuthError as e:
        print(f"Authentication failed: {str(e)}")
        sys.exit(1)

