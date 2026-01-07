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
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunklib import client as splunk_client

# Add lib directory to path
sys.path.insert(0, make_splunkhome_path(['etc', 'apps', 'TA-trellix-epo', 'bin']))

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
        Authenticate with ePO and get/refresh token
        
        Args:
            session_key: Splunk session key (optional, for credential storage)
            
        Returns:
            Authentication token string
            
        Raises:
            TrellixEPOAuthError: If authentication fails
        """
        # Use existing token if valid
        if self.token and self._is_token_valid():
            return self.token
        
        # Retrieve credentials if session_key provided
        if session_key and self.username:
            stored_user, stored_pass = self._get_stored_credentials(session_key, self.username)
            if stored_user and stored_pass:
                self.username = stored_user
                self.password = stored_pass
        
        # Validate credentials
        if not self.username or not self.password:
            raise TrellixEPOAuthError("Username and password are required for authentication")
        
        # Authenticate with ePO
        try:
            auth_url = f"{self.base_url}/core.authenticate"
            
            # Use basic auth for authentication endpoint
            auth = HTTPBasicAuth(self.username, self.password)
            
            response = self.session.post(
                auth_url,
                auth=auth,
                params={'user': self.username},
                timeout=30
            )
            
            response.raise_for_status()
            
            # Parse response
            if response.text:
                try:
                    result = response.json()
                    if isinstance(result, dict) and 'result' in result:
                        token = result['result']
                    else:
                        token = result if isinstance(result, str) else response.text.strip('"')
                except json.JSONDecodeError:
                    token = response.text.strip('"').strip("'")
                
                # Cache token
                self.token = token
                self.token_cache = token
                self.token_expiry = time.time() + 3600  # Assume 1 hour expiry
                
                logger.info("Successfully authenticated with ePO")
                return token
            else:
                raise TrellixEPOAuthError("Empty response from authentication endpoint")
                
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
        
        Args:
            token: Authentication token (optional, uses instance token if not provided)
            
        Returns:
            Dictionary with authentication headers
        """
        if token:
            auth_token = token
        elif self.token:
            auth_token = self.token
        else:
            raise TrellixEPOAuthError("No authentication token available")
        
        return {
            'Authorization': f'Basic {base64.b64encode(f"{auth_token}:".encode()).decode()}',
            'Content-Type': 'application/json'
        }
    
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

