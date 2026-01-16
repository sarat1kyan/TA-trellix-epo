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
    
    # =========================================================================
    # NEW v2.0.0 DATA COLLECTION METHODS
    # These methods query specific ePO tables for comprehensive data collection
    # =========================================================================
    
    def execute_table_query(self, table: str, columns: List[str] = None,
                            where: str = None, limit: int = 1000) -> List[Dict]:
        """
        Execute a query against a specific ePO table
        
        Uses core.executeQuery with table parameter to retrieve data from
        specific ePO database tables like EPOEvents, PWS_ThreatSummary, etc.
        
        Args:
            table: The ePO table name (e.g., 'EPOEvents', 'PWS_ThreatSummary')
            columns: Optional list of columns to select (default: all)
            where: Optional WHERE clause for filtering
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of dictionaries with query results
        """
        try:
            # Build query parameters
            params = {
                'target': table,
            }
            
            if columns:
                params['select'] = ','.join(columns)
            
            if where:
                params['where'] = where
            
            # Use core.executeQuery with table target
            result = self._make_request('core.executeQuery', params)
            
            if result is None:
                return []
            
            if isinstance(result, list):
                return result
            elif isinstance(result, str):
                return self._parse_text_response(result)
            elif isinstance(result, dict):
                return [result] if result else []
            
            return []
            
        except TrellixEPOClientError as e:
            logger.warning(f"Table query failed for {table}: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error querying table {table}: {str(e)}")
            return []
    
    def get_threat_summary(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve threat summary data including escalated, resolved, and unresolved threats
        
        Queries PWS_ThreatSummary and PWS_Threat tables for comprehensive
        threat status information as displayed in ePO dashboard.
        
        Args:
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of threat summary dictionaries with fields:
            - threat_status: Escalated/Resolved/Unresolved
            - threat_type: Type of threat
            - resolution_type: Advanced/Basic (for resolved threats)
            - affected_count: Number of affected systems
            - severity: Threat severity level
        """
        all_threats = []
        
        # Try PWS_ThreatSummary table first
        try:
            result = self.execute_table_query('PWS_ThreatSummary')
            if result:
                for item in result:
                    item['source_table'] = 'PWS_ThreatSummary'
                all_threats.extend(result)
        except Exception as e:
            logger.debug(f"PWS_ThreatSummary query failed: {str(e)}")
        
        # Also try PWS_Threat for detailed threat info
        try:
            result = self.execute_table_query('PWS_Threat')
            if result:
                for item in result:
                    item['source_table'] = 'PWS_Threat'
                all_threats.extend(result)
        except Exception as e:
            logger.debug(f"PWS_Threat query failed: {str(e)}")
        
        # Try EPExtendedEvent for detailed threat events
        try:
            result = self.execute_table_query('EPExtendedEvent')
            if result:
                for item in result:
                    item['source_table'] = 'EPExtendedEvent'
                all_threats.extend(result)
        except Exception as e:
            logger.debug(f"EPExtendedEvent query failed: {str(e)}")
        
        # Fallback to EPOEvents if no specific threat tables available
        if not all_threats:
            try:
                result = self.execute_table_query('EPOEvents')
                if result:
                    for item in result:
                        item['source_table'] = 'EPOEvents'
                    all_threats.extend(result)
            except Exception as e:
                logger.debug(f"EPOEvents query failed: {str(e)}")
        
        # Try saved queries as last resort
        if not all_threats:
            try:
                queries = self.get_available_queries()
                threat_keywords = ['threat', 'escalat', 'unresolv', 'resolv', 'pws']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in threat_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found threat summary query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_threats.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_threats[:limit], 'threat_summary')
    
    def get_software_status(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve software deployment status for all Trellix products
        
        Queries EPOSystemProductVersionInfo table for product installation
        status across managed endpoints.
        
        Args:
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of software status dictionaries with fields:
            - product_name: Name of the product
            - product_version: Installed version
            - install_count: Number of installations
            - status: Deployment status (Deployed/Pending/Failed)
        """
        all_software = []
        
        # Primary table: EPOSystemProductVersionInfo
        try:
            result = self.execute_table_query('EPOSystemProductVersionInfo')
            if result:
                for item in result:
                    item['source_table'] = 'EPOSystemProductVersionInfo'
                all_software.extend(result)
        except Exception as e:
            logger.debug(f"EPOSystemProductVersionInfo query failed: {str(e)}")
        
        # Try rollup tables for aggregated product info
        rollup_tables = [
            'EPORollup_ProductProperties_ENS',
            'EPORollup_ProductProperties_TP',
            'EPORollup_ProductProperties_FW',
            'EPORollup_ProductProperties_WC',
            'EPORollup_ProductProperties_ATP',
            'EPORollup_ProductProperties_DXL',
            'EPORollup_ProductProperties_UDLP',
            'EPORollup_ProductProperties_MA',
        ]
        
        for table in rollup_tables:
            try:
                result = self.execute_table_query(table)
                if result:
                    product_name = table.replace('EPORollup_ProductProperties_', '')
                    for item in result:
                        item['source_table'] = table
                        item['product_code'] = product_name
                    all_software.extend(result)
            except Exception as e:
                logger.debug(f"{table} query failed: {str(e)}")
        
        # Fallback to saved queries
        if not all_software:
            try:
                queries = self.get_available_queries()
                software_keywords = ['product', 'software', 'version', 'deploy', 'install']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in software_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found software query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_software.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_software[:limit], 'software_status')
    
    def get_compliance_overview(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve compliance overview data including security content compliance
        
        Queries EpoRollup_ComplianceHistory and SCOR_VW_NON_COMPLIANT_AGENT tables.
        
        Args:
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of compliance dictionaries with fields:
            - content_type: Type of security content
            - compliance_pct: Compliance percentage
            - compliant_count: Number of compliant systems
            - non_compliant_count: Number of non-compliant systems
        """
        all_compliance = []
        
        # Try compliance history rollup
        try:
            result = self.execute_table_query('EpoRollup_ComplianceHistory')
            if result:
                for item in result:
                    item['source_table'] = 'EpoRollup_ComplianceHistory'
                all_compliance.extend(result)
        except Exception as e:
            logger.debug(f"EpoRollup_ComplianceHistory query failed: {str(e)}")
        
        # Try Solidcore non-compliant agents view
        try:
            result = self.execute_table_query('SCOR_VW_NON_COMPLIANT_AGENT')
            if result:
                for item in result:
                    item['source_table'] = 'SCOR_VW_NON_COMPLIANT_AGENT'
                    item['compliance_status'] = 'Non-Compliant'
                all_compliance.extend(result)
        except Exception as e:
            logger.debug(f"SCOR_VW_NON_COMPLIANT_AGENT query failed: {str(e)}")
        
        # Try SCOR_FEATURES_STATUS for feature compliance
        try:
            result = self.execute_table_query('SCOR_FEATURES_STATUS')
            if result:
                for item in result:
                    item['source_table'] = 'SCOR_FEATURES_STATUS'
                all_compliance.extend(result)
        except Exception as e:
            logger.debug(f"SCOR_FEATURES_STATUS query failed: {str(e)}")
        
        # Fallback to saved queries
        if not all_compliance:
            try:
                queries = self.get_available_queries()
                compliance_keywords = ['compliance', 'compliant', 'content', 'security']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in compliance_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found compliance query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_compliance.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_compliance[:limit], 'compliance_overview')
    
    def get_dlp_incidents(self, start_time: Union[datetime, str] = None,
                          end_time: Union[datetime, str] = None,
                          limit: int = 1000) -> List[Dict]:
        """
        Retrieve Data Loss Prevention (DLP) incidents
        
        Queries UDLP_EPD_Incidents and related DLP tables.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of DLP incident dictionaries with fields:
            - incident_id: Unique incident identifier
            - severity: Incident severity
            - source_host: Source system
            - destination: Data destination
            - rule_name: Triggered DLP rule
            - action_taken: Action performed
            - data_classification: Data classification level
        """
        all_incidents = []
        
        # Primary DLP tables
        dlp_tables = [
            'UDLP_EPD_Incidents',
            'UDLP_IncidentsQueriesView',
            'UDLP_Operationals',
        ]
        
        for table in dlp_tables:
            try:
                result = self.execute_table_query(table)
                if result:
                    for item in result:
                        item['source_table'] = table
                    all_incidents.extend(result)
            except Exception as e:
                logger.debug(f"{table} query failed: {str(e)}")
        
        # Fallback to saved queries
        if not all_incidents:
            try:
                queries = self.get_available_queries()
                dlp_keywords = ['dlp', 'data loss', 'incident', 'udlp', 'protection']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in dlp_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found DLP query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_incidents.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_incidents[:limit], 'dlp_incidents')
    
    def get_device_management(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve device management status including check-in failures and protection status
        
        Queries MAEnforcementStatusView and MARebootPendingView tables.
        
        Args:
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of device management dictionaries with fields:
            - host: Hostname
            - last_checkin: Last agent check-in time
            - days_since_checkin: Days since last check-in
            - protection_status: Protection status
            - agent_status: Agent enforcement status
            - reboot_pending: Whether reboot is pending
        """
        all_devices = []
        
        # Agent enforcement status
        try:
            result = self.execute_table_query('MAEnforcementStatusView')
            if result:
                for item in result:
                    item['source_table'] = 'MAEnforcementStatusView'
                all_devices.extend(result)
        except Exception as e:
            logger.debug(f"MAEnforcementStatusView query failed: {str(e)}")
        
        # Reboot pending status
        try:
            result = self.execute_table_query('MARebootPendingView')
            if result:
                for item in result:
                    item['source_table'] = 'MARebootPendingView'
                    item['reboot_pending'] = True
                all_devices.extend(result)
        except Exception as e:
            logger.debug(f"MARebootPendingView query failed: {str(e)}")
        
        # Try EPOLeafNode for managed state
        try:
            result = self.execute_table_query('EPOLeafNode')
            if result:
                for item in result:
                    item['source_table'] = 'EPOLeafNode'
                    # Calculate check-in status
                    managed_state = item.get('ManagedState')
                    item['protection_status'] = 'Protected' if managed_state == 1 else 'Unprotected'
                all_devices.extend(result)
        except Exception as e:
            logger.debug(f"EPOLeafNode query failed: {str(e)}")
        
        # Fallback to saved queries
        if not all_devices:
            try:
                queries = self.get_available_queries()
                device_keywords = ['device', 'check-in', 'checkin', 'unprotected', 'agent', 'managed']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in device_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found device query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_devices.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_devices[:limit], 'device_management')
    
    def get_edr_events(self, start_time: Union[datetime, str] = None,
                       end_time: Union[datetime, str] = None,
                       limit: int = 1000) -> List[Dict]:
        """
        Retrieve Endpoint Detection and Response (EDR) events
        
        Queries MVEDRCustomEvent and TIE (Threat Intelligence Exchange) tables.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of EDR event dictionaries with fields:
            - event_type: Type of EDR event
            - host: Affected hostname
            - process_name: Process involved
            - file_hash: File hash
            - reputation: Reputation score/status
            - action: Action taken
        """
        all_events = []
        
        # EDR custom events
        try:
            result = self.execute_table_query('MVEDRCustomEvent')
            if result:
                for item in result:
                    item['source_table'] = 'MVEDRCustomEvent'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"MVEDRCustomEvent query failed: {str(e)}")
        
        # EDR properties
        try:
            result = self.execute_table_query('MVEDRProperties')
            if result:
                for item in result:
                    item['source_table'] = 'MVEDRProperties'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"MVEDRProperties query failed: {str(e)}")
        
        # TIE file reputation
        try:
            result = self.execute_table_query('TieServerSchema.fileJoined')
            if result:
                for item in result:
                    item['source_table'] = 'TieServerSchema.fileJoined'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"TieServerSchema.fileJoined query failed: {str(e)}")
        
        # TIE certificate reputation
        try:
            result = self.execute_table_query('TieServerSchema.certificateJoined')
            if result:
                for item in result:
                    item['source_table'] = 'TieServerSchema.certificateJoined'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"TieServerSchema.certificateJoined query failed: {str(e)}")
        
        # Fallback to saved queries
        if not all_events:
            try:
                queries = self.get_available_queries()
                edr_keywords = ['edr', 'detection', 'response', 'tie', 'reputation', 'mvedr']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in edr_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found EDR query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_events.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_events[:limit], 'edr_events')
    
    def get_web_control_events(self, start_time: Union[datetime, str] = None,
                                end_time: Union[datetime, str] = None,
                                limit: int = 1000) -> List[Dict]:
        """
        Retrieve Web Control events
        
        Queries WP_EventInfo table for web filtering events.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of web control event dictionaries with fields:
            - host: Source hostname
            - url: Accessed URL
            - category: URL category
            - action: Action taken (Allow/Block)
            - user: Username
        """
        all_events = []
        
        # Web Control events
        try:
            result = self.execute_table_query('WP_EventInfo')
            if result:
                for item in result:
                    item['source_table'] = 'WP_EventInfo'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"WP_EventInfo query failed: {str(e)}")
        
        # Fallback to saved queries
        if not all_events:
            try:
                queries = self.get_available_queries()
                web_keywords = ['web', 'url', 'filter', 'category', 'block', 'wp_']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in web_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found web control query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_events.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_events[:limit], 'web_control_events')
    
    def get_firewall_rules(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve Firewall rules and configuration
        
        Queries FW_Rule and FW_NamedNetwork tables.
        
        Args:
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of firewall rule dictionaries with fields:
            - rule_name: Name of the rule
            - action: Rule action (Allow/Block)
            - direction: Traffic direction
            - protocol: Network protocol
            - source_ip: Source IP/network
            - dest_ip: Destination IP/network
            - port: Port number(s)
        """
        all_rules = []
        
        # Firewall rules
        try:
            result = self.execute_table_query('FW_Rule')
            if result:
                for item in result:
                    item['source_table'] = 'FW_Rule'
                all_rules.extend(result)
        except Exception as e:
            logger.debug(f"FW_Rule query failed: {str(e)}")
        
        # Named networks
        try:
            result = self.execute_table_query('FW_NamedNetwork')
            if result:
                for item in result:
                    item['source_table'] = 'FW_NamedNetwork'
                all_rules.extend(result)
        except Exception as e:
            logger.debug(f"FW_NamedNetwork query failed: {str(e)}")
        
        # Firewall applications
        try:
            result = self.execute_table_query('FW_Application')
            if result:
                for item in result:
                    item['source_table'] = 'FW_Application'
                all_rules.extend(result)
        except Exception as e:
            logger.debug(f"FW_Application query failed: {str(e)}")
        
        # Fallback to saved queries
        if not all_rules:
            try:
                queries = self.get_available_queries()
                fw_keywords = ['firewall', 'fw_', 'rule', 'network']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in fw_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found firewall query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_rules.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_rules[:limit], 'firewall_events')
    
    def get_app_control_events(self, start_time: Union[datetime, str] = None,
                                end_time: Union[datetime, str] = None,
                                limit: int = 1000) -> List[Dict]:
        """
        Retrieve Application Control (Solidcore) events
        
        Queries SCOR_EVENTS and SCOR_VW_INVENTORY tables.
        
        Args:
            start_time: Start time filter (datetime or ISO string)
            end_time: End time filter (datetime or ISO string)
            limit: Maximum number of results (default: 1000)
            
        Returns:
            List of application control event dictionaries with fields:
            - host: Hostname
            - application: Application name
            - action: Action taken (Allow/Block/Observe)
            - path: Application path
            - checksum: Application checksum
            - user: Username
        """
        all_events = []
        
        # Solidcore events
        try:
            result = self.execute_table_query('SCOR_EVENTS')
            if result:
                for item in result:
                    item['source_table'] = 'SCOR_EVENTS'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"SCOR_EVENTS query failed: {str(e)}")
        
        # Solidcore inventory
        try:
            result = self.execute_table_query('SCOR_VW_INVENTORY')
            if result:
                for item in result:
                    item['source_table'] = 'SCOR_VW_INVENTORY'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"SCOR_VW_INVENTORY query failed: {str(e)}")
        
        # Solidcore alerts
        try:
            result = self.execute_table_query('SCOR_ALERTS')
            if result:
                for item in result:
                    item['source_table'] = 'SCOR_ALERTS'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"SCOR_ALERTS query failed: {str(e)}")
        
        # Solidcore status
        try:
            result = self.execute_table_query('SCOR_VW_STATUS')
            if result:
                for item in result:
                    item['source_table'] = 'SCOR_VW_STATUS'
                all_events.extend(result)
        except Exception as e:
            logger.debug(f"SCOR_VW_STATUS query failed: {str(e)}")
        
        # Fallback to saved queries
        if not all_events:
            try:
                queries = self.get_available_queries()
                app_keywords = ['solidcore', 'scor', 'application control', 'whitelist', 'inventory']
                
                for query in queries:
                    name = query.get('Name', '').lower()
                    if any(kw in name for kw in app_keywords):
                        qid = query.get('Id')
                        if qid:
                            logger.info(f"Found app control query: {query.get('Name')} (ID: {qid})")
                            result = self.execute_query(int(qid))
                            if result:
                                all_events.extend(result)
                                break
            except Exception as e:
                logger.debug(f"Saved query search failed: {str(e)}")
        
        return self._normalize_events(all_events[:limit], 'app_control_events')
    
    # =========================================================================
    # END OF NEW v2.0.0 DATA COLLECTION METHODS
    # =========================================================================
    
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

