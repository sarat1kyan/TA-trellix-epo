#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Trellix ePO REST API Client
Handles all API interactions with Trellix ePO server
"""

import sys
import os
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlencode

# Add lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from trellix_epo_auth import TrellixEPOAuth, TrellixEPOAuthError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


class TrellixEPOClientError(Exception):
    """Custom exception for client errors"""
    pass


class TrellixEPOClient:
    """
    Client for interacting with Trellix ePO REST API
    Handles all data retrieval operations with pagination and error handling
    """
    
    def __init__(self, auth_handler: TrellixEPOAuth, session_key=None):
        """
        Initialize ePO API client
        
        Args:
            auth_handler: TrellixEPOAuth instance for authentication
            session_key: Splunk session key (optional)
        """
        self.auth = auth_handler
        self.session_key = session_key
        self.base_url = auth_handler.base_url
        self.session = auth_handler.session
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1  # 100ms between requests
        
    def _rate_limit(self):
        """Implement rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    def _make_request(self, command, params=None, method='GET'):
        """
        Make API request to ePO
        
        Args:
            command: ePO command (e.g., 'system.find')
            params: Request parameters
            method: HTTP method (GET or POST)
            
        Returns:
            Response data as dictionary or list
            
        Raises:
            TrellixEPOClientError: If request fails
        """
        self._rate_limit()
        
        # Authenticate if needed
        if not self.auth.token:
            self.auth.authenticate(self.session_key)
        
        # Build URL
        url = f"{self.base_url}/{command}"
        
        # Get auth headers
        headers = self.auth.get_auth_headers()
        
        # Make request
        try:
            if method.upper() == 'POST':
                response = self.session.post(
                    url,
                    headers=headers,
                    json=params or {},
                    timeout=60
                )
            else:
                response = self.session.get(
                    url,
                    headers=headers,
                    params=params or {},
                    timeout=60
                )
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                return self._make_request(command, params, method)
            
            response.raise_for_status()
            
            # Parse response
            content_type = response.headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                data = response.json()
                
                # Handle ePO response format
                if isinstance(data, dict):
                    if 'result' in data:
                        return data['result']
                    elif 'error' in data:
                        raise TrellixEPOClientError(f"API error: {data['error']}")
                
                return data
            else:
                # Try to parse as JSON anyway
                try:
                    return response.json()
                except:
                    return response.text
                    
        except requests.exceptions.Timeout:
            raise TrellixEPOClientError(f"Request timeout for command: {command}")
        except requests.exceptions.RequestException as e:
            # Try to re-authenticate on 401
            if hasattr(e.response, 'status_code') and e.response.status_code == 401:
                logger.info("Authentication expired, re-authenticating...")
                self.auth.authenticate(self.session_key)
                return self._make_request(command, params, method)
            raise TrellixEPOClientError(f"API request failed: {str(e)}")
    
    def get_threat_events(self, start_time=None, end_time=None, limit=1000):
        """
        Retrieve threat detection events
        
        Args:
            start_time: Start time (datetime or ISO string)
            end_time: End time (datetime or ISO string)
            limit: Maximum number of results
            
        Returns:
            List of threat event dictionaries
        """
        params = {}
        
        if start_time:
            if isinstance(start_time, datetime):
                params['startTime'] = start_time.isoformat()
            else:
                params['startTime'] = start_time
        
        if end_time:
            if isinstance(end_time, datetime):
                params['endTime'] = end_time.isoformat()
            else:
                params['endTime'] = end_time
        
        params[':output'] = 'json'
        params['limit'] = limit
        
        try:
            # Use threat detection query
            result = self._make_request('epo.threat.detection', params)
            
            # Handle different response formats
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'result' in result:
                return result['result'] if isinstance(result['result'], list) else [result['result']]
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving threat events: {str(e)}")
            return []
    
    def get_malware_detections(self, start_time=None, end_time=None, limit=1000):
        """
        Retrieve malware detection events
        
        Args:
            start_time: Start time (datetime or ISO string)
            end_time: End time (datetime or ISO string)
            limit: Maximum number of results
            
        Returns:
            List of malware detection dictionaries
        """
        params = {}
        
        if start_time:
            if isinstance(start_time, datetime):
                params['startTime'] = start_time.isoformat()
            else:
                params['startTime'] = start_time
        
        if end_time:
            if isinstance(end_time, datetime):
                params['endTime'] = end_time.isoformat()
            else:
                params['endTime'] = end_time
        
        params[':output'] = 'json'
        params['limit'] = limit
        
        try:
            result = self._make_request('epo.threat.malware', params)
            
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'result' in result:
                return result['result'] if isinstance(result['result'], list) else [result['result']]
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving malware detections: {str(e)}")
            return []
    
    def get_host_status(self, limit=1000):
        """
        Retrieve host status information
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of host status dictionaries
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        try:
            result = self._make_request('core.systemInfo', params)
            
            if isinstance(result, list):
                return result
            elif isinstance(result, dict):
                # If single system, convert to list
                return [result] if result else []
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving host status: {str(e)}")
            # Fallback to system.find
            return self._get_systems_fallback(limit)
    
    def _get_systems_fallback(self, limit=1000):
        """Fallback method to get systems using system.find"""
        params = {
            ':output': 'json',
            'searchText': '',
            'limit': limit
        }
        
        try:
            result = self._make_request('system.find', params)
            return result if isinstance(result, list) else []
        except Exception as e:
            logger.error(f"Fallback system retrieval failed: {str(e)}")
            return []
    
    def get_agent_status(self, limit=1000):
        """
        Retrieve agent status information
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of agent status dictionaries
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        try:
            result = self._make_request('epo.clienttask.find', params)
            
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'result' in result:
                return result['result'] if isinstance(result['result'], list) else [result['result']]
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving agent status: {str(e)}")
            return []
    
    def get_policy_compliance(self, start_time=None, end_time=None, limit=1000):
        """
        Retrieve policy compliance information
        
        Args:
            start_time: Start time (datetime or ISO string)
            end_time: End time (datetime or ISO string)
            limit: Maximum number of results
            
        Returns:
            List of policy compliance dictionaries
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if start_time:
            if isinstance(start_time, datetime):
                params['startTime'] = start_time.isoformat()
            else:
                params['startTime'] = start_time
        
        if end_time:
            if isinstance(end_time, datetime):
                params['endTime'] = end_time.isoformat()
            else:
                params['endTime'] = end_time
        
        try:
            result = self._make_request('epo.compliance.query', params)
            
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'result' in result:
                return result['result'] if isinstance(result['result'], list) else [result['result']]
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving policy compliance: {str(e)}")
            return []
    
    def get_quarantine_events(self, start_time=None, end_time=None, limit=1000):
        """
        Retrieve quarantine events
        
        Args:
            start_time: Start time (datetime or ISO string)
            end_time: End time (datetime or ISO string)
            limit: Maximum number of results
            
        Returns:
            List of quarantine event dictionaries
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if start_time:
            if isinstance(start_time, datetime):
                params['startTime'] = start_time.isoformat()
            else:
                params['startTime'] = start_time
        
        if end_time:
            if isinstance(end_time, datetime):
                params['endTime'] = end_time.isoformat()
            else:
                params['endTime'] = end_time
        
        try:
            result = self._make_request('epo.quarantine.query', params)
            
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'result' in result:
                return result['result'] if isinstance(result['result'], list) else [result['result']]
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving quarantine events: {str(e)}")
            return []
    
    def get_updates(self, limit=1000):
        """
        Retrieve DAT update information
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of update dictionaries
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        try:
            result = self._make_request('epo.dat.query', params)
            
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'result' in result:
                return result['result'] if isinstance(result['result'], list) else [result['result']]
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving updates: {str(e)}")
            return []
    
    def get_user_actions(self, start_time=None, end_time=None, limit=1000):
        """
        Retrieve user action audit logs
        
        Args:
            start_time: Start time (datetime or ISO string)
            end_time: End time (datetime or ISO string)
            limit: Maximum number of results
            
        Returns:
            List of user action dictionaries
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if start_time:
            if isinstance(start_time, datetime):
                params['startTime'] = start_time.isoformat()
            else:
                params['startTime'] = start_time
        
        if end_time:
            if isinstance(end_time, datetime):
                params['endTime'] = end_time.isoformat()
            else:
                params['endTime'] = end_time
        
        try:
            result = self._make_request('epo.audit.query', params)
            
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'result' in result:
                return result['result'] if isinstance(result['result'], list) else [result['result']]
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving user actions: {str(e)}")
            return []


if __name__ == "__main__":
    # Test client
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: trellix_epo_client.py <epo_url> <username> <password> [port]")
        sys.exit(1)
    
    epo_url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 8443
    
    from trellix_epo_auth import TrellixEPOAuth
    
    auth = TrellixEPOAuth(epo_url, port, username, password)
    client = TrellixEPOClient(auth)
    
    try:
        # Test connection
        token = auth.authenticate()
        print(f"Authentication successful")
        
        # Test API call
        hosts = client.get_host_status(limit=10)
        print(f"Retrieved {len(hosts)} hosts")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

