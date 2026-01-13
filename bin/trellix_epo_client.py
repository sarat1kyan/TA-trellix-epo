#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Trellix ePO REST API Client
Handles all API interactions with Trellix ePO server

This client provides methods to retrieve various security telemetry from
Trellix (McAfee) ePolicy Orchestrator using its REST API.

Trellix ePO REST API Reference:
- Base URL format: https://{server}:{port}/remote/{command}
- Authentication: Token-based or Basic authentication
- Output format: JSON (specified via :output parameter)

Supported commands:
- core.authenticate: Get authentication token
- core.systemInfo: System information
- system.find: Find systems by criteria
- epo.threat.detection: Threat detection events
- epo.threat.malware: Malware detection events
- epo.compliance.query: Policy compliance data
- epo.quarantine.query: Quarantine events
- epo.audit.query: User audit logs
- epo.dat.query: DAT version information
"""

import sys
import os
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlencode, quote

# Add bin directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from trellix_epo_auth import TrellixEPOAuth, TrellixEPOAuthError

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s level=%(levelname)s app=TA-trellix-epo %(name)s: %(message)s'
)
logger = logging.getLogger('trellix_epo_client')


class TrellixEPOClientError(Exception):
    """Custom exception for API client errors"""
    def __init__(self, message: str, status_code: int = None, response_body: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class TrellixEPOClient:
    """
    Client for interacting with Trellix ePO REST API
    
    Handles all data retrieval operations with:
    - Automatic authentication and token refresh
    - Pagination for large result sets
    - Rate limiting to prevent API overload
    - Error handling and retry logic
    - Response parsing and normalization
    """
    
    # Standard ePO API commands
    API_COMMANDS = {
        'authenticate': 'core.authenticate',
        'system_info': 'core.systemInfo',
        'system_find': 'system.find',
        'system_tree': 'system.findGroups',
        'threat_events': 'epo.threat.detection',
        'malware_detections': 'epo.threat.malware',
        'policy_compliance': 'epo.compliance.query',
        'quarantine': 'epo.quarantine.query',
        'audit': 'epo.audit.query',
        'dat_updates': 'epo.dat.query',
        'client_tasks': 'epo.clienttask.find',
        'agent_handler': 'agenthandler.query',
    }
    
    def __init__(self, auth_handler: TrellixEPOAuth, session_key: str = None, 
                 timeout: int = 60, retry_attempts: int = 3):
        """
        Initialize ePO API client
        
        Args:
            auth_handler: TrellixEPOAuth instance for authentication
            session_key: Splunk session key for credential retrieval (optional)
            timeout: Request timeout in seconds (default: 60)
            retry_attempts: Number of retry attempts for failed requests (default: 3)
        """
        self.auth = auth_handler
        self.session_key = session_key
        self.base_url = auth_handler.base_url
        self.session = auth_handler.session
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        
        # Rate limiting configuration
        self.last_request_time = 0
        self.min_request_interval = 0.2  # 200ms between requests (5 req/sec max)
        self.rate_limit_backoff = 60  # Default backoff for 429 responses
        
    def _rate_limit(self):
        """
        Implement rate limiting to prevent API overload
        
        Ensures minimum interval between requests to avoid
        triggering rate limits on the ePO server.
        """
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def _parse_epo_response(self, response_text: str) -> Any:
        """
        Parse ePO API response which may have 'OK:' prefix
        
        ePO API often returns responses in format: OK:{"result": [...]}
        
        Args:
            response_text: Raw response text from API
            
        Returns:
            Parsed JSON data
        """
        text = response_text.strip()
        
        # Handle ePO prefix format (OK:, ERROR:, etc.)
        if text.startswith('OK:'):
            text = text[3:].strip()
        elif text.startswith('ERROR:'):
            error_msg = text[6:].strip()
            raise TrellixEPOClientError(f"ePO API Error: {error_msg}")
        
        # Try to parse as JSON
        try:
            data = json.loads(text)
            return data
        except json.JSONDecodeError:
            # Return as-is if not valid JSON
            return text
    
    def _make_request(self, command: str, params: Dict = None, method: str = 'GET',
                      attempt: int = 1) -> Any:
        """
        Make API request to ePO server with retry logic
        
        Args:
            command: ePO command (e.g., 'system.find')
            params: Request parameters dictionary
            method: HTTP method (GET or POST)
            attempt: Current retry attempt number
            
        Returns:
            Response data as dictionary, list, or string
            
        Raises:
            TrellixEPOClientError: If request fails after all retries
        """
        self._rate_limit()
        
        # Authenticate if no token available
        if not self.auth.token:
            try:
                self.auth.authenticate(self.session_key)
            except TrellixEPOAuthError as e:
                raise TrellixEPOClientError(f"Authentication failed: {str(e)}")
        
        # Build request URL
        url = f"{self.base_url}/{command}"
        
        # Build headers with authentication
        headers = self.auth.get_auth_headers()
        headers['Accept'] = 'application/json'
        
        # Ensure output format is JSON
        request_params = params.copy() if params else {}
        if ':output' not in request_params:
            request_params[':output'] = 'json'
        
        logger.debug(f"Making request to {command} (attempt {attempt})")
        
        try:
            if method.upper() == 'POST':
                response = self.session.post(
                    url,
                    headers=headers,
                    json=request_params,
                    timeout=self.timeout
                )
            else:
                response = self.session.get(
                    url,
                    headers=headers,
                    params=request_params,
                    timeout=self.timeout
                )
            
            # Handle rate limiting (429)
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', self.rate_limit_backoff))
                logger.warning(f"Rate limited (429). Waiting {retry_after} seconds before retry...")
                time.sleep(retry_after)
                if attempt < self.retry_attempts:
                    return self._make_request(command, params, method, attempt + 1)
                raise TrellixEPOClientError(
                    f"Rate limited after {attempt} attempts",
                    status_code=429
                )
            
            # Handle authentication errors (401)
            if response.status_code == 401:
                if attempt < 2:  # Only retry once for auth
                    logger.info("Authentication expired, refreshing token...")
                    self.auth.token = None
                    self.auth.authenticate(self.session_key)
                    return self._make_request(command, params, method, attempt + 1)
                raise TrellixEPOClientError(
                    "Authentication failed after token refresh",
                    status_code=401
                )
            
            # Handle server errors with retry
            if response.status_code >= 500:
                if attempt < self.retry_attempts:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.warning(f"Server error {response.status_code}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    return self._make_request(command, params, method, attempt + 1)
                raise TrellixEPOClientError(
                    f"Server error after {attempt} attempts: {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text[:500]
                )
            
            # Raise for other HTTP errors
            response.raise_for_status()
            
            # Parse response based on content type
            content_type = response.headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                data = response.json()
            else:
                # ePO may return text with OK: prefix
                data = self._parse_epo_response(response.text)
            
            # Handle ePO response format
            if isinstance(data, dict):
                if 'result' in data:
                    return data['result']
                elif 'error' in data:
                    raise TrellixEPOClientError(f"ePO API error: {data['error']}")
                elif 'errorMessage' in data:
                    raise TrellixEPOClientError(f"ePO API error: {data['errorMessage']}")
            
            return data
                    
        except requests.exceptions.Timeout:
            if attempt < self.retry_attempts:
                logger.warning(f"Request timeout for {command}. Retrying...")
                return self._make_request(command, params, method, attempt + 1)
            raise TrellixEPOClientError(
                f"Request timeout after {attempt} attempts for command: {command}"
            )
        except requests.exceptions.ConnectionError as e:
            if attempt < self.retry_attempts:
                wait_time = 2 ** attempt
                logger.warning(f"Connection error. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                return self._make_request(command, params, method, attempt + 1)
            raise TrellixEPOClientError(f"Connection failed: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise TrellixEPOClientError(f"Request failed: {str(e)}")
    
    def _normalize_time_param(self, time_value: Union[datetime, str, None]) -> Optional[str]:
        """
        Normalize time parameter to ISO format string
        
        Args:
            time_value: datetime object or ISO string
            
        Returns:
            ISO formatted time string or None
        """
        if time_value is None:
            return None
        if isinstance(time_value, datetime):
            return time_value.strftime('%Y-%m-%dT%H:%M:%S')
        return str(time_value)
    
    def _normalize_events(self, events: List[Dict], event_type: str) -> List[Dict]:
        """
        Normalize event data for consistent field naming
        
        Args:
            events: List of event dictionaries from API
            event_type: Type of event for metadata
            
        Returns:
            List of normalized event dictionaries
        """
        normalized = []
        for event in events:
            if not isinstance(event, dict):
                continue
            
            # Add metadata
            event['epo_event_type'] = event_type
            event['collection_time'] = datetime.utcnow().isoformat()
            
            # Normalize common fields
            field_mappings = {
                # Computer/Host fields
                'ComputerName': 'computerName',
                'computer_name': 'computerName',
                'NodeName': 'computerName',
                'hostname': 'computerName',
                
                # IP fields
                'IPAddress': 'ipAddress',
                'ip_address': 'ipAddress',
                'IP': 'ipAddress',
                
                # User fields
                'UserName': 'userName',
                'user_name': 'userName',
                'User': 'userName',
                
                # Timestamp fields
                'DetectedUTC': 'detectedUTC',
                'detected_utc': 'detectedUTC',
                'EventTime': 'detectedUTC',
            }
            
            for old_key, new_key in field_mappings.items():
                if old_key in event and new_key not in event:
                    event[new_key] = event[old_key]
            
            normalized.append(event)
        
        return normalized
    
    def get_threat_events(self, start_time: Union[datetime, str] = None, 
                          end_time: Union[datetime, str] = None, 
                          limit: int = 1000) -> List[Dict]:
        """
        Retrieve threat detection events from ePO
        
        Gets threat events including viruses, malware, and other security threats
        detected by endpoint protection.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of threat event dictionaries with fields:
            - detectionId: Unique detection identifier
            - threatName: Name of the detected threat
            - threatType: Type/category of threat
            - severity: Severity level (Low, Medium, High, Critical)
            - computerName: Affected computer name
            - ipAddress: IP address of affected system
            - detectedUTC: Detection timestamp in UTC
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if start_time:
            params['startTime'] = self._normalize_time_param(start_time)
        if end_time:
            params['endTime'] = self._normalize_time_param(end_time)
        
        try:
            # Try primary threat detection command
            result = self._make_request(self.API_COMMANDS.get('threat_events', 'epo.threat.detection'), params)
            
            # Normalize result to list
            if result is None:
                return []
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            else:
                logger.warning(f"Unexpected threat events response type: {type(result)}")
                return []
            
            return self._normalize_events(events, 'threat_events')
                
        except TrellixEPOClientError as e:
            logger.error(f"Error retrieving threat events: {str(e)}")
            # Try fallback query if primary fails
            try:
                return self._get_threat_events_fallback(start_time, end_time, limit)
            except Exception:
                return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving threat events: {str(e)}")
            return []
    
    def _get_threat_events_fallback(self, start_time=None, end_time=None, limit=1000):
        """Fallback method for threat events using alternative queries"""
        # Try using core query with threat filter
        params = {
            ':output': 'json',
            'limit': limit,
            'searchText': 'threat'
        }
        try:
            result = self._make_request('core.executeQuery', params)
            if isinstance(result, list):
                return self._normalize_events(result, 'threat_events')
        except:
            pass
        return []
    
    def get_malware_detections(self, start_time: Union[datetime, str] = None, 
                                end_time: Union[datetime, str] = None, 
                                limit: int = 1000) -> List[Dict]:
        """
        Retrieve malware detection events from ePO
        
        Gets detailed malware detection events including file information,
        detection action, and affected system details.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of malware detection dictionaries with fields:
            - malwareName: Name of the detected malware
            - malwareType: Type/category of malware
            - filePath: Path to the infected file
            - fileHash: MD5/SHA hash of the file
            - threatId: Associated threat identifier
            - computerName: Affected computer name
            - userName: User context when detected
            - detectedUTC: Detection timestamp in UTC
            - action: Action taken (cleaned, deleted, quarantined)
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if start_time:
            params['startTime'] = self._normalize_time_param(start_time)
        if end_time:
            params['endTime'] = self._normalize_time_param(end_time)
        
        try:
            result = self._make_request(
                self.API_COMMANDS.get('malware_detections', 'epo.threat.malware'), 
                params
            )
            
            if result is None:
                return []
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            else:
                return []
            
            return self._normalize_events(events, 'malware_detections')
                
        except TrellixEPOClientError as e:
            logger.error(f"Error retrieving malware detections: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving malware detections: {str(e)}")
            return []
    
    def get_host_status(self, limit: int = 1000, 
                        search_filter: str = None) -> List[Dict]:
        """
        Retrieve host/system status information from ePO
        
        Gets system information including OS details, agent version,
        DAT version, and last update times.
        
        Args:
            limit: Maximum number of results (default: 1000)
            search_filter: Optional filter for host names/IPs
            
        Returns:
            List of host status dictionaries with fields:
            - computerName: Computer/hostname
            - operatingSystem: OS name and version
            - ipAddress: IP address
            - agentVersion: ePO agent version
            - datVersion: DAT/signature version
            - engineVersion: Scan engine version
            - lastUpdateTime: Last DAT update timestamp
            - agentStatus: Current agent status
            - managed: Whether system is managed by ePO
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if search_filter:
            params['searchText'] = search_filter
        
        try:
            # Try primary systemInfo command
            result = self._make_request(
                self.API_COMMANDS.get('system_info', 'core.systemInfo'), 
                params
            )
            
            if result is None:
                return self._get_systems_fallback(limit, search_filter)
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            else:
                return self._get_systems_fallback(limit, search_filter)
            
            return self._normalize_events(events, 'host_status')
                
        except TrellixEPOClientError as e:
            logger.warning(f"Primary host status query failed: {str(e)}")
            return self._get_systems_fallback(limit, search_filter)
        except Exception as e:
            logger.error(f"Unexpected error retrieving host status: {str(e)}")
            return []
    
    def _get_systems_fallback(self, limit: int = 1000, 
                              search_filter: str = None) -> List[Dict]:
        """
        Fallback method to get systems using system.find command
        
        Args:
            limit: Maximum number of results
            search_filter: Optional search filter
            
        Returns:
            List of system dictionaries
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if search_filter:
            params['searchText'] = search_filter
        else:
            params['searchText'] = ''
        
        try:
            result = self._make_request(
                self.API_COMMANDS.get('system_find', 'system.find'), 
                params
            )
            
            if isinstance(result, list):
                return self._normalize_events(result, 'host_status')
            elif isinstance(result, dict):
                return self._normalize_events([result], 'host_status') if result else []
            return []
            
        except Exception as e:
            logger.error(f"Fallback system retrieval failed: {str(e)}")
            return []
    
    def get_agent_status(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve ePO agent status information
        
        Gets agent connectivity status, version information,
        and last communication times.
        
        Args:
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of agent status dictionaries with fields:
            - computerName: Computer/hostname
            - agentVersion: Agent version
            - agentStatus: Connection status (Active, Inactive)
            - lastCommunicationTime: Last agent check-in time
            - tags: Assigned system tags
            - nodeId: ePO node identifier
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        try:
            # Try client task find for agent info
            result = self._make_request(
                self.API_COMMANDS.get('client_tasks', 'epo.clienttask.find'), 
                params
            )
            
            if result is None:
                return []
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            else:
                return []
            
            return self._normalize_events(events, 'agent_status')
                
        except TrellixEPOClientError as e:
            logger.error(f"Error retrieving agent status: {str(e)}")
            # Try using system.find as fallback for basic agent info
            return self._get_systems_fallback(limit)
        except Exception as e:
            logger.error(f"Unexpected error retrieving agent status: {str(e)}")
            return []
    
    def get_policy_compliance(self, start_time: Union[datetime, str] = None, 
                               end_time: Union[datetime, str] = None, 
                               limit: int = 1000) -> List[Dict]:
        """
        Retrieve policy compliance information from ePO
        
        Gets policy compliance status for managed systems including
        violations, non-compliance events, and policy status.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of policy compliance dictionaries with fields:
            - computerName: Computer/hostname
            - policyName: Name of the policy
            - complianceStatus: Status (Compliant, Non-Compliant, Unknown)
            - violationCount: Number of violations
            - checkedUTC: Last compliance check timestamp
            - policyVersion: Version of the policy
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if start_time:
            params['startTime'] = self._normalize_time_param(start_time)
        if end_time:
            params['endTime'] = self._normalize_time_param(end_time)
        
        try:
            result = self._make_request(
                self.API_COMMANDS.get('policy_compliance', 'epo.compliance.query'), 
                params
            )
            
            if result is None:
                return []
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            else:
                return []
            
            return self._normalize_events(events, 'policy_compliance')
                
        except TrellixEPOClientError as e:
            logger.error(f"Error retrieving policy compliance: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving policy compliance: {str(e)}")
            return []
    
    def get_quarantine_events(self, start_time: Union[datetime, str] = None, 
                               end_time: Union[datetime, str] = None, 
                               limit: int = 1000) -> List[Dict]:
        """
        Retrieve quarantine events from ePO
        
        Gets quarantine actions including files that were quarantined,
        restored, or deleted.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of quarantine event dictionaries with fields:
            - computerName: Computer/hostname
            - filePath: Path to the quarantined file
            - fileHash: File hash (MD5/SHA)
            - action: Quarantine action (quarantined, restored, deleted)
            - quarantinedUTC: Quarantine timestamp
            - threatName: Associated threat name
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if start_time:
            params['startTime'] = self._normalize_time_param(start_time)
        if end_time:
            params['endTime'] = self._normalize_time_param(end_time)
        
        try:
            result = self._make_request(
                self.API_COMMANDS.get('quarantine', 'epo.quarantine.query'), 
                params
            )
            
            if result is None:
                return []
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            else:
                return []
            
            return self._normalize_events(events, 'quarantine_events')
                
        except TrellixEPOClientError as e:
            logger.error(f"Error retrieving quarantine events: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving quarantine events: {str(e)}")
            return []
    
    def get_updates(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve DAT/engine update information from ePO
        
        Gets signature and engine update status for managed systems.
        
        Args:
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of update dictionaries with fields:
            - computerName: Computer/hostname
            - datVersion: DAT/signature version number
            - engineVersion: Scan engine version
            - updateStatus: Update status
            - lastUpdateTime: Last successful update timestamp
            - pendingUpdates: Number of pending updates
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        try:
            result = self._make_request(
                self.API_COMMANDS.get('dat_updates', 'epo.dat.query'), 
                params
            )
            
            if result is None:
                return []
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            else:
                return []
            
            return self._normalize_events(events, 'updates')
                
        except TrellixEPOClientError as e:
            logger.error(f"Error retrieving updates: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving updates: {str(e)}")
            return []
    
    def get_user_actions(self, start_time: Union[datetime, str] = None, 
                          end_time: Union[datetime, str] = None, 
                          limit: int = 1000) -> List[Dict]:
        """
        Retrieve user action audit logs from ePO
        
        Gets audit trail of user activities in the ePO console including
        logins, policy changes, and administrative actions.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of user action dictionaries with fields:
            - userName: User who performed the action
            - action: Action type (login, modify, create, delete)
            - objectName: Target object of the action
            - result: Action result (success, failure)
            - sourceIP: Source IP address
            - timestampUTC: Action timestamp in UTC
        """
        params = {
            ':output': 'json',
            'limit': limit
        }
        
        if start_time:
            params['startTime'] = self._normalize_time_param(start_time)
        if end_time:
            params['endTime'] = self._normalize_time_param(end_time)
        
        try:
            result = self._make_request(
                self.API_COMMANDS.get('audit', 'epo.audit.query'), 
                params
            )
            
            if result is None:
                return []
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            else:
                return []
            
            return self._normalize_events(events, 'user_actions')
                
        except TrellixEPOClientError as e:
            logger.error(f"Error retrieving user actions: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving user actions: {str(e)}")
            return []
    
    def test_connection(self) -> tuple:
        """
        Test connection to ePO server
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Try to authenticate and get server info
            self.auth.authenticate(self.session_key)
            
            # Make a simple API call to verify connectivity
            result = self._make_request('core.help', {':output': 'json'})
            
            return (True, "Connection successful")
            
        except TrellixEPOAuthError as e:
            return (False, f"Authentication failed: {str(e)}")
        except TrellixEPOClientError as e:
            return (False, f"API error: {str(e)}")
        except Exception as e:
            return (False, f"Connection failed: {str(e)}")


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

