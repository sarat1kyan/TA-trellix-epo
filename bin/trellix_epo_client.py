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

# Add Splunk's Python library paths (for requests, urllib3, etc.)
SPLUNK_HOME = os.environ.get('SPLUNK_HOME', '/opt/splunk')
splunk_lib_paths = [
    os.path.join(SPLUNK_HOME, 'lib', 'python3.9', 'site-packages'),
    os.path.join(SPLUNK_HOME, 'lib', 'python3.7', 'site-packages'),
]
for lib_path in splunk_lib_paths:
    if os.path.isdir(lib_path) and lib_path not in sys.path:
        sys.path.insert(0, lib_path)

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
    # Note: Trellix ePO uses text-based responses with "OK:" prefix
    # Most data retrieval uses system.find and core.executeQuery
    API_COMMANDS = {
        'authenticate': 'core.authenticate',
        'system_find': 'system.find',
        'system_tree': 'system.findGroups',
        'list_queries': 'core.listQueries',
        'execute_query': 'core.executeQuery',
        'list_tables': 'core.listTables',
        'client_tasks': 'clienttask.find',
        'agent_handlers': 'agentmgmt.listAgentHandlers',
        'core_help': 'core.help',
    }
    
    # Field name mappings from ePO text format to normalized format
    # ePO returns "System Name" but we want "computerName" for CIM
    FIELD_MAPPINGS = {
        'System Name': 'computerName',
        'System Location': 'systemLocation',
        'IP address': 'ipAddress',
        'IP4 Address (deprecated)': 'ipv4Address',
        'User Name': 'userName',
        'Domain Name': 'domainName',
        'DNS Name': 'dnsName',
        'OS Type': 'osType',
        'OS Version': 'osVersion',
        'OS Platform': 'osPlatform',
        'OS Build Number': 'osBuildNumber',
        'MAC Address': 'macAddress',
        'CPU Type': 'cpuType',
        'CPU Speed (MHz)': 'cpuSpeed',
        'Number Of CPUs': 'cpuCount',
        'Total Physical Memory': 'totalMemory',
        'Free Memory': 'freeMemory',
        'Free Disk Space': 'freeDiskSpace',
        'Total Disk Space': 'totalDiskSpace',
        'Is 64-bit OS': 'is64Bit',
        'Agent Handler': 'agentHandler',
        'Last Communication': 'lastCommunication',
        'Tags': 'tags',
        'Excluded Tags': 'excludedTags',
        'Custom 1': 'custom1',
        'Custom 2': 'custom2',
        'Custom 3': 'custom3',
        'Custom 4': 'custom4',
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
        
        ePO API returns responses in text format:
        OK:
        Field1: Value1
        Field2: Value2
        
        Or sometimes JSON after OK:
        
        Args:
            response_text: Raw response text from API
            
        Returns:
            Parsed data (list of dicts for multi-record, dict for single, or raw text)
        """
        text = response_text.strip()
        
        # Handle ePO prefix format (OK:, ERROR:, etc.)
        if text.startswith('OK:'):
            text = text[3:].strip()
        elif text.startswith('ERROR:') or text.startswith('Error'):
            error_msg = text.split(':', 1)[1].strip() if ':' in text else text
            raise TrellixEPOClientError(f"ePO API Error: {error_msg}")
        
        # Try to parse as JSON first
        try:
            data = json.loads(text)
            return data
        except json.JSONDecodeError:
            pass
        
        # Parse text format (key: value pairs, separated by blank lines for records)
        return self._parse_text_response(text)
    
    def _parse_text_response(self, text: str) -> List[Dict]:
        """
        Parse ePO text format response into list of dictionaries
        
        Format:
        Field1: Value1
        Field2: Value2
        
        Field1: Value3
        Field2: Value4
        
        Args:
            text: Text response from ePO
            
        Returns:
            List of dictionaries, one per record
        """
        records = []
        current_record = {}
        
        for line in text.split('\n'):
            line = line.strip()
            
            # Empty line indicates new record
            if not line:
                if current_record:
                    records.append(self._normalize_record(current_record))
                    current_record = {}
                continue
            
            # Parse "Key: Value" format
            if ':' in line:
                # Handle case where value might contain colons (like IP addresses)
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    
                    # Handle "null" and "N/A" values
                    if value.lower() in ('null', 'n/a', ''):
                        value = None
                    
                    current_record[key] = value
        
        # Don't forget the last record
        if current_record:
            records.append(self._normalize_record(current_record))
        
        return records
    
    def _normalize_record(self, record: Dict) -> Dict:
        """
        Normalize field names in a record using FIELD_MAPPINGS
        
        Args:
            record: Dictionary with original field names
            
        Returns:
            Dictionary with normalized field names
        """
        normalized = {}
        for key, value in record.items():
            # Use mapped name if available, otherwise convert to camelCase
            if key in self.FIELD_MAPPINGS:
                normalized_key = self.FIELD_MAPPINGS[key]
            else:
                # Convert "Field Name" to "fieldName"
                words = key.split()
                if words:
                    normalized_key = words[0].lower() + ''.join(w.capitalize() for w in words[1:])
                else:
                    normalized_key = key
            
            normalized[normalized_key] = value
            # Also keep original key for reference
            normalized[key] = value
        
        return normalized
    
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
        
        # Validate we have credentials (basic auth is used on every request)
        if not self.auth.username or not self.auth.password:
            raise TrellixEPOClientError("No credentials configured - set username and password")
        
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
        
        # Use requests' built-in basic auth
        from requests.auth import HTTPBasicAuth
        auth = HTTPBasicAuth(self.auth.username, self.auth.password)
        
        try:
            if method.upper() == 'POST':
                response = self.session.post(
                    url,
                    auth=auth,
                    headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
                    json=request_params,
                    timeout=self.timeout
                )
            else:
                response = self.session.get(
                    url,
                    auth=auth,
                    headers={'Accept': 'application/json'},
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
                raise TrellixEPOClientError(
                    "Authentication failed - check username and password",
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
    
    def get_available_queries(self) -> List[Dict]:
        """
        List all available queries in ePO
        
        Returns:
            List of query dictionaries with id, name, description
        """
        try:
            result = self._make_request('core.listQueries', {})
            
            if isinstance(result, list):
                return result
            elif isinstance(result, str):
                # Parse text format
                return self._parse_query_list(result)
            return []
        except Exception as e:
            logger.error(f"Error listing queries: {str(e)}")
            return []
    
    def _parse_query_list(self, text: str) -> List[Dict]:
        """Parse core.listQueries text response into list of query dicts"""
        queries = []
        current_query = {}
        
        for line in text.split('\n'):
            line = line.strip()
            if not line:
                if current_query and 'Id' in current_query:
                    queries.append(current_query)
                    current_query = {}
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                current_query[key.strip()] = value.strip()
        
        if current_query and 'Id' in current_query:
            queries.append(current_query)
        
        return queries
    
    def execute_query(self, query_id: int) -> List[Dict]:
        """
        Execute a saved query by ID
        
        Args:
            query_id: The query ID from core.listQueries
            
        Returns:
            List of result dictionaries
        """
        try:
            result = self._make_request('core.executeQuery', {'queryId': query_id})
            
            if isinstance(result, list):
                return result
            elif isinstance(result, str):
                return self._parse_text_response(result)
            return []
        except TrellixEPOClientError as e:
            logger.error(f"Error executing query {query_id}: {str(e)}")
            return []
    
    def get_threat_events(self, start_time: Union[datetime, str] = None, 
                          end_time: Union[datetime, str] = None, 
                          limit: int = 1000,
                          query_id: int = None) -> List[Dict]:
        """
        Retrieve threat detection events from ePO
        
        Note: Trellix ePO may require a saved query for threat events.
        If query_id is provided, uses core.executeQuery.
        Otherwise attempts to find threat-related queries automatically.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            query_id: Optional specific query ID to execute
            
        Returns:
            List of threat event dictionaries
        """
        # If specific query_id provided, use it
        if query_id:
            try:
                result = self.execute_query(query_id)
                return self._normalize_events(result, 'threat_events')
            except Exception as e:
                logger.error(f"Error executing threat query {query_id}: {str(e)}")
                return []
        
        # Try to find threat-related queries automatically
        try:
            queries = self.get_available_queries()
            threat_keywords = ['threat', 'malware', 'virus', 'detection', 'attack', 'security']
            
            for query in queries:
                name = query.get('Name', '').lower()
                desc = query.get('Description', '').lower()
                
                if any(kw in name or kw in desc for kw in threat_keywords):
                    qid = query.get('Id')
                    if qid:
                        logger.info(f"Found threat query: {query.get('Name')} (ID: {qid})")
                        result = self.execute_query(int(qid))
                        if result:
                            return self._normalize_events(result, 'threat_events')
            
            logger.warning("No threat-related queries found in ePO. Create a threat query in ePO console.")
            return []
            
        except Exception as e:
            logger.error(f"Error retrieving threat events: {str(e)}")
            return []
    
    def get_malware_detections(self, start_time: Union[datetime, str] = None, 
                                end_time: Union[datetime, str] = None, 
                                limit: int = 1000,
                                query_id: int = None) -> List[Dict]:
        """
        Retrieve malware detection events from ePO
        
        Note: Uses saved queries in ePO. If no query_id provided,
        searches for malware-related queries automatically.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            query_id: Optional specific query ID to execute
            
        Returns:
            List of malware detection dictionaries
        """
        if query_id:
            try:
                result = self.execute_query(query_id)
                return self._normalize_events(result, 'malware_detections')
            except Exception as e:
                logger.error(f"Error executing malware query {query_id}: {str(e)}")
                return []
        
        # Try to find malware-related queries
        try:
            queries = self.get_available_queries()
            malware_keywords = ['malware', 'virus', 'trojan', 'infection', 'detected']
            
            for query in queries:
                name = query.get('Name', '').lower()
                desc = query.get('Description', '').lower()
                
                if any(kw in name or kw in desc for kw in malware_keywords):
                    qid = query.get('Id')
                    if qid:
                        logger.info(f"Found malware query: {query.get('Name')} (ID: {qid})")
                        result = self.execute_query(int(qid))
                        if result:
                            return self._normalize_events(result, 'malware_detections')
            
            logger.warning("No malware-related queries found in ePO.")
            return []
            
        except Exception as e:
            logger.error(f"Error retrieving malware detections: {str(e)}")
            return []
    
    def get_host_status(self, limit: int = 1000, 
                        search_filter: str = None) -> List[Dict]:
        """
        Retrieve host/system status information from ePO
        
        Uses system.find command which returns text format:
        System Name: HOSTNAME
        IP address: 192.168.x.x
        OS Type: Windows 11
        Last Communication: 1/15/26 5:40:12 PM AMT
        
        Args:
            limit: Maximum number of results (default: 1000)
            search_filter: Optional filter for host names/IPs
            
        Returns:
            List of host status dictionaries with normalized fields
        """
        params = {}
        
        # searchText is required for system.find, use empty string for all
        params['searchText'] = search_filter if search_filter else ''
        
        try:
            result = self._make_request('system.find', params)
            
            if result is None:
                return []
            
            # Result should be a list of dicts from _parse_text_response
            if isinstance(result, list):
                events = result
            elif isinstance(result, dict):
                events = [result] if result else []
            elif isinstance(result, str):
                # If still a string, try parsing again
                events = self._parse_text_response(result)
            else:
                logger.warning(f"Unexpected host status response type: {type(result)}")
                return []
            
            return self._normalize_events(events, 'host_status')
                
        except TrellixEPOClientError as e:
            logger.error(f"Error retrieving host status: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving host status: {str(e)}")
            return []
    
    def get_agent_status(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve ePO agent status information
        
        Uses system.find which includes Last Communication time and Agent Handler.
        
        Args:
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of agent status dictionaries with fields from system.find:
            - computerName: Computer/hostname
            - lastCommunication: Last agent check-in time
            - agentHandler: Agent handler ID
            - tags: Assigned system tags
        """
        # Agent status comes from system.find - same data, different context
        try:
            result = self._make_request('system.find', {'searchText': ''})
            
            if result is None:
                return []
            
            if isinstance(result, list):
                events = result
            elif isinstance(result, str):
                events = self._parse_text_response(result)
            else:
                events = []
            
            # Add agent-specific metadata
            for event in events:
                event['epo_event_type'] = 'agent_status'
                # Determine agent status based on last communication
                last_comm = event.get('lastCommunication') or event.get('Last Communication')
                if last_comm:
                    event['agentStatus'] = 'Active'  # Has communicated
                else:
                    event['agentStatus'] = 'Unknown'
            
            return self._normalize_events(events, 'agent_status')
                
        except Exception as e:
            logger.error(f"Error retrieving agent status: {str(e)}")
            return []
    
    def get_policy_compliance(self, start_time: Union[datetime, str] = None, 
                               end_time: Union[datetime, str] = None, 
                               limit: int = 1000,
                               query_id: int = None) -> List[Dict]:
        """
        Retrieve policy compliance information from ePO
        
        Uses saved queries. Query ID 4 is typically "Policy Assignment Change History".
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            query_id: Optional specific query ID (default: tries to find policy queries)
            
        Returns:
            List of policy compliance dictionaries
        """
        # Try query ID 4 first (Policy Assignment Change History based on user's ePO)
        if query_id is None:
            query_id = 4  # Default to policy history query shown in user's ePO
        
        try:
            result = self.execute_query(query_id)
            if result:
                return self._normalize_events(result, 'policy_compliance')
        except Exception as e:
            logger.debug(f"Query {query_id} failed: {str(e)}")
        
        # Try to find policy-related queries
        try:
            queries = self.get_available_queries()
            policy_keywords = ['policy', 'compliance', 'assignment', 'violation']
            
            for query in queries:
                name = query.get('Name', '').lower()
                desc = query.get('Description', '').lower()
                
                if any(kw in name or kw in desc for kw in policy_keywords):
                    qid = query.get('Id')
                    if qid and int(qid) != query_id:  # Skip already tried
                        logger.info(f"Found policy query: {query.get('Name')} (ID: {qid})")
                        result = self.execute_query(int(qid))
                        if result:
                            return self._normalize_events(result, 'policy_compliance')
            
            logger.warning("No policy compliance data retrieved.")
            return []
            
        except Exception as e:
            logger.error(f"Error retrieving policy compliance: {str(e)}")
            return []
    
    def get_quarantine_events(self, start_time: Union[datetime, str] = None, 
                               end_time: Union[datetime, str] = None, 
                               limit: int = 1000,
                               query_id: int = None) -> List[Dict]:
        """
        Retrieve quarantine events from ePO
        
        Uses saved queries. Searches for quarantine-related queries.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            query_id: Optional specific query ID
            
        Returns:
            List of quarantine event dictionaries
        """
        if query_id:
            try:
                result = self.execute_query(query_id)
                return self._normalize_events(result, 'quarantine_events')
            except Exception as e:
                logger.error(f"Error executing quarantine query {query_id}: {str(e)}")
                return []
        
        # Try to find quarantine-related queries
        try:
            queries = self.get_available_queries()
            quarantine_keywords = ['quarantine', 'quarantined', 'isolated']
            
            for query in queries:
                name = query.get('Name', '').lower()
                desc = query.get('Description', '').lower()
                
                if any(kw in name or kw in desc for kw in quarantine_keywords):
                    qid = query.get('Id')
                    if qid:
                        logger.info(f"Found quarantine query: {query.get('Name')} (ID: {qid})")
                        result = self.execute_query(int(qid))
                        if result:
                            return self._normalize_events(result, 'quarantine_events')
            
            logger.warning("No quarantine queries found in ePO.")
            return []
            
        except Exception as e:
            logger.error(f"Error retrieving quarantine events: {str(e)}")
            return []
    
    def get_updates(self, limit: int = 1000, query_id: int = None) -> List[Dict]:
        """
        Retrieve DAT/engine update information from ePO
        
        Uses system.find which includes basic system info.
        For detailed DAT info, use a saved query.
        
        Args:
            limit: Maximum number of results (default: 1000)
            query_id: Optional specific query ID for DAT details
            
        Returns:
            List of update dictionaries from system.find
        """
        if query_id:
            try:
                result = self.execute_query(query_id)
                return self._normalize_events(result, 'updates')
            except Exception as e:
                logger.error(f"Error executing updates query {query_id}: {str(e)}")
        
        # Try to find DAT/update-related queries
        try:
            queries = self.get_available_queries()
            update_keywords = ['dat', 'update', 'signature', 'version', 'engine']
            
            for query in queries:
                name = query.get('Name', '').lower()
                desc = query.get('Description', '').lower()
                
                if any(kw in name or kw in desc for kw in update_keywords):
                    qid = query.get('Id')
                    if qid:
                        logger.info(f"Found update query: {query.get('Name')} (ID: {qid})")
                        result = self.execute_query(int(qid))
                        if result:
                            return self._normalize_events(result, 'updates')
        except Exception as e:
            logger.debug(f"Query search failed: {str(e)}")
        
        # Fallback: use system.find data (has basic system info)
        try:
            result = self._make_request('system.find', {'searchText': ''})
            
            if isinstance(result, list):
                events = result
            elif isinstance(result, str):
                events = self._parse_text_response(result)
            else:
                return []
            
            return self._normalize_events(events, 'updates')
            
        except Exception as e:
            logger.error(f"Error retrieving updates: {str(e)}")
            return []
    
    def get_user_actions(self, start_time: Union[datetime, str] = None, 
                          end_time: Union[datetime, str] = None, 
                          limit: int = 1000,
                          query_id: int = None) -> List[Dict]:
        """
        Retrieve user action audit logs from ePO
        
        Uses saved queries that target OrionAuditLog table.
        Query ID 4 is "Policy Assignment Change History by User".
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            query_id: Optional specific query ID
            
        Returns:
            List of user action dictionaries
        """
        if query_id:
            try:
                result = self.execute_query(query_id)
                return self._normalize_events(result, 'user_actions')
            except Exception as e:
                logger.error(f"Error executing audit query {query_id}: {str(e)}")
                return []
        
        # Try to find audit-related queries
        try:
            queries = self.get_available_queries()
            audit_keywords = ['audit', 'user', 'action', 'history', 'log', 'activity']
            
            for query in queries:
                name = query.get('Name', '').lower()
                desc = query.get('Description', '').lower()
                target = query.get('Target', '').lower()
                
                # Prefer queries targeting audit log
                if 'auditlog' in target.lower() or any(kw in name or kw in desc for kw in audit_keywords):
                    qid = query.get('Id')
                    if qid:
                        logger.info(f"Found audit query: {query.get('Name')} (ID: {qid})")
                        result = self.execute_query(int(qid))
                        if result:
                            return self._normalize_events(result, 'user_actions')
            
            logger.warning("No audit queries found in ePO.")
            return []
            
        except Exception as e:
            logger.error(f"Error retrieving user actions: {str(e)}")
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

