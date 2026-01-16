# Utils package for TA-trellix-epo
"""
Utility functions for Trellix ePO Splunk Add-on

This module provides common utility functions used across the add-on.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Union

# Python 3.2+ has timezone support, but provide fallback for older versions
try:
    from datetime import timezone
    UTC = timezone.utc
except ImportError:
    # Fallback for Python < 3.2 (unlikely but safe)
    import time
    class _UTC:
        """Simple UTC timezone implementation"""
        def utcoffset(self, dt):
            return datetime.timedelta(0)
        def tzname(self, dt):
            return "UTC"
        def dst(self, dt):
            return datetime.timedelta(0)
    UTC = _UTC()

# Configure logging
logger = logging.getLogger('trellix_epo_utils')


def get_splunk_home() -> str:
    """
    Get Splunk home directory from environment
    
    Returns:
        Path to Splunk home directory
    """
    return os.environ.get('SPLUNK_HOME', '/opt/splunk')


def get_app_dir() -> str:
    """
    Get the TA-trellix-epo app directory
    
    Returns:
        Path to app directory
    """
    return os.path.join(get_splunk_home(), 'etc', 'apps', 'TA-trellix-epo')


def parse_boolean(value: Any) -> bool:
    """
    Parse various boolean representations to Python bool
    
    Args:
        value: Value to parse (string, bool, int, etc.)
        
    Returns:
        Boolean value
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', 'yes', '1', 'on', 'enabled')
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def parse_integer(value: Any, default: int = 0) -> int:
    """
    Safely parse integer from various types
    
    Args:
        value: Value to parse
        default: Default value if parsing fails
        
    Returns:
        Integer value
    """
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def format_timestamp(dt: Union[datetime, str, float, None], 
                     format_str: str = '%Y-%m-%dT%H:%M:%SZ') -> Optional[str]:
    """
    Format timestamp to ISO format string
    
    Args:
        dt: Datetime object, ISO string, or Unix timestamp
        format_str: Output format string
        
    Returns:
        Formatted timestamp string or None
    """
    if dt is None:
        return None
    
    if isinstance(dt, str):
        try:
            # Try to parse ISO format
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except ValueError:
            return dt
    elif isinstance(dt, (int, float)):
        dt = datetime.fromtimestamp(dt, tz=UTC)
    
    if isinstance(dt, datetime):
        return dt.strftime(format_str)
    
    return str(dt)


def safe_json_loads(data: str, default: Any = None) -> Any:
    """
    Safely parse JSON string
    
    Args:
        data: JSON string to parse
        default: Default value if parsing fails
        
    Returns:
        Parsed data or default value
    """
    if not data:
        return default
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return default


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Sanitize string for safe logging/storage
    
    Args:
        value: String to sanitize
        max_length: Maximum length to truncate to
        
    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Remove null bytes and control characters
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')
    
    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length] + '...'
    
    return value


def mask_sensitive_data(data: Dict[str, Any], 
                        sensitive_keys: tuple = ('password', 'token', 'secret', 'key', 'credential')) -> Dict[str, Any]:
    """
    Mask sensitive data in a dictionary for safe logging
    
    Args:
        data: Dictionary containing potentially sensitive data
        sensitive_keys: Tuple of key patterns to mask
        
    Returns:
        Dictionary with sensitive values masked
    """
    masked = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(sk in key_lower for sk in sensitive_keys):
            masked[key] = '********'
        elif isinstance(value, dict):
            masked[key] = mask_sensitive_data(value, sensitive_keys)
        else:
            masked[key] = value
    return masked


class EventNormalizer:
    """
    Utility class for normalizing event data to consistent format
    """
    
    # Standard field mappings for normalization
    FIELD_MAPPINGS = {
        # Host/Computer fields
        'ComputerName': 'host',
        'computer_name': 'host',
        'computerName': 'host',
        'NodeName': 'host',
        'hostname': 'host',
        'Hostname': 'host',
        
        # IP Address fields
        'IPAddress': 'src_ip',
        'ip_address': 'src_ip',
        'ipAddress': 'src_ip',
        'IP': 'src_ip',
        'SourceIP': 'src_ip',
        'sourceIP': 'src_ip',
        
        # User fields
        'UserName': 'user',
        'user_name': 'user',
        'userName': 'user',
        'User': 'user',
        
        # Threat fields
        'ThreatName': 'threat_name',
        'threatName': 'threat_name',
        'MalwareName': 'malware_name',
        'malwareName': 'malware_name',
        
        # Severity fields
        'Severity': 'severity',
        'RiskLevel': 'severity',
        'Priority': 'severity',
    }
    
    @classmethod
    def normalize(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize event fields to standard names
        
        Args:
            event: Event dictionary
            
        Returns:
            Normalized event dictionary
        """
        normalized = event.copy()
        
        for old_key, new_key in cls.FIELD_MAPPINGS.items():
            if old_key in normalized and new_key not in normalized:
                normalized[new_key] = normalized[old_key]
        
        return normalized
