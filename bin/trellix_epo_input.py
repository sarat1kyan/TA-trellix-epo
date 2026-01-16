#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Trellix ePO Modular Input for Splunk
Main entry point for data collection from Trellix ePO REST API

This modular input connects to Trellix (McAfee) ePO servers via REST API
and collects security telemetry for ingestion into Splunk.

Supported data types:
- threat_events: Threat detection events
- malware_detections: Malware detection events
- host_status: System host status information
- agent_status: ePO agent status information
- policy_compliance: Policy compliance violations
- quarantine_events: Quarantine-related events
- updates: DAT update information
- user_actions: User action audit logs
"""

import sys
import os
import json
import logging
import time
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

# Add bin directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Add Splunk's Python library paths
SPLUNK_HOME = os.environ.get('SPLUNK_HOME', '/opt/splunk')

# Core Splunk Python paths
splunk_lib_paths = [
    os.path.join(SPLUNK_HOME, 'lib', 'python3.9', 'site-packages'),
    os.path.join(SPLUNK_HOME, 'lib', 'python3.7', 'site-packages'),
]
for lib_path in splunk_lib_paths:
    if os.path.isdir(lib_path) and lib_path not in sys.path:
        sys.path.insert(0, lib_path)

# splunklib is not bundled with Splunk core - look for it in apps that include it
# Check our own lib folder first, then fall back to other apps
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
        # Check if this path contains splunklib
        if os.path.isdir(os.path.join(abs_path, 'splunklib')):
            sys.path.insert(0, abs_path)
            break

# Splunk libraries
try:
    from splunklib.modularinput import Script, Scheme, Argument, EventWriter
    from splunklib.modularinput.event import Event
    from splunklib.binding import connect
    SPLUNKLIB_AVAILABLE = True
except ImportError as e:
    # splunklib not available - this will cause the modular input to fail
    SPLUNKLIB_AVAILABLE = False
    Script = object  # Placeholder to allow class definition
    logging.error(f"splunklib not available: {e}. Modular input will not function.")

# Import our modules
try:
    from trellix_epo_auth import TrellixEPOAuth, TrellixEPOAuthError
    from trellix_epo_client import TrellixEPOClient, TrellixEPOClientError
except ImportError as e:
    logging.error(f"Failed to import Trellix ePO modules: {str(e)}")
    raise

# Configure logging - send to stderr for Splunk to capture
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s level=%(levelname)s app=TA-trellix-epo %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger('trellix_epo_input')


class TrellixEPOInput(Script):
    """
    Splunk Modular Input for Trellix ePO
    Collects security telemetry from ePO REST API
    """
    
    def get_scheme(self):
        """Define input scheme and arguments"""
        scheme = Scheme("Trellix ePO Input")
        scheme.description = "Collects security telemetry from Trellix (McAfee) ePO server"
        scheme.use_external_validation = True
        scheme.use_single_instance = False
        
        # Input name argument
        scheme.add_argument(Argument(
            "name",
            title="Input Name",
            description="Unique name for this input instance",
            required_on_create=True
        ))
        
        # Data source type
        scheme.add_argument(Argument(
            "input_type",
            title="Data Source Type",
            description="Type of data to collect",
            required_on_create=True,
            data_type=Argument.data_type_string
        ))
        
        # ePO Configuration
        scheme.add_argument(Argument(
            "epo_url",
            title="ePO Server URL",
            description="ePO server hostname or IP address",
            required_on_create=True
        ))
        
        scheme.add_argument(Argument(
            "epo_port",
            title="ePO Server Port",
            description="ePO server port (default: 8443)",
            required_on_create=False,
            data_type=Argument.data_type_number
        ))
        
        scheme.add_argument(Argument(
            "epo_username",
            title="ePO Username",
            description="Username for ePO authentication",
            required_on_create=True
        ))
        
        scheme.add_argument(Argument(
            "epo_password",
            title="ePO Password",
            description="Password for ePO authentication (stored securely)",
            required_on_create=True
        ))
        
        scheme.add_argument(Argument(
            "epo_token",
            title="ePO Token (Optional)",
            description="Pre-existing ePO authentication token (optional)",
            required_on_create=False
        ))
        
        scheme.add_argument(Argument(
            "ssl_verify",
            title="Verify SSL",
            description="Verify SSL certificates (true/false)",
            required_on_create=False,
            data_type=Argument.data_type_boolean
        ))
        
        # Polling configuration
        scheme.add_argument(Argument(
            "polling_interval",
            title="Polling Interval (seconds)",
            description="How often to poll for new data",
            required_on_create=False,
            data_type=Argument.data_type_number
        ))
        
        scheme.add_argument(Argument(
            "batch_size",
            title="Batch Size",
            description="Maximum number of events per batch",
            required_on_create=False,
            data_type=Argument.data_type_number
        ))
        
        # Note: "index" and "sourcetype" are reserved internal Splunk arguments
        # They are handled automatically by Splunk and should NOT be defined here
        # Configure them in inputs.conf instead
        
        # Checkpoint configuration
        scheme.add_argument(Argument(
            "checkpoint_dir",
            title="Checkpoint Directory",
            description="Directory to store checkpoints for incremental collection",
            required_on_create=False
        ))
        
        return scheme
    
    def validate_input(self, definition):
        """Validate input configuration"""
        try:
            # Validate required fields
            if not definition.parameters.get('epo_url'):
                raise ValueError("ePO URL is required")
            
            if not definition.parameters.get('input_type'):
                raise ValueError("Input type is required")
            
            if not definition.parameters.get('epo_username'):
                raise ValueError("ePO username is required")
            
            # Test connection
            epo_url = definition.parameters['epo_url']
            port = int(definition.parameters.get('epo_port', 8443))
            username = definition.parameters['epo_username']
            password = definition.parameters.get('epo_password', '')
            ssl_verify = str(definition.parameters.get('ssl_verify', 'true')).lower() == 'true'
            
            auth = TrellixEPOAuth(epo_url, port, username, password, ssl_verify=ssl_verify)
            success, message = auth.test_connection()
            
            if not success:
                raise ValueError(f"Connection test failed: {message}")
                
        except Exception as e:
            logger.error(f"Input validation failed: {str(e)}")
            raise ValueError(f"Validation error: {str(e)}")
    
    def stream_events(self, inputs, ew):
        """Main streaming function - collects and emits events"""
        
        for input_name, input_item in inputs.inputs.items():
            try:
                self._collect_events(input_name, input_item, ew)
            except Exception as e:
                error_msg = f"Error processing input {input_name}: {str(e)}\n{traceback.format_exc()}"
                logger.error(error_msg)
                ew.log(EventWriter.ERROR, error_msg)
    
    def _load_global_settings(self, session_key):
        """
        Load global settings from ta_trellix_epo_settings.conf
        
        Args:
            session_key: Splunk session key for API access
            
        Returns:
            Dictionary with global settings
        """
        settings = {
            'epo_server': '',
            'epo_port': 8443,
            'username': '',
            'verify_ssl': True,
            'use_ssl': True,
            'timeout': 60,
            'retry_attempts': 3,
            'batch_size': 1000,
            'polling_interval': 300,
            'log_level': 'INFO'
        }
        
        try:
            # Try to read from conf file using Splunk's bundled config reader
            import splunk.clilib.cli_common as cli_common
            conf = cli_common.getConfStanza('ta_trellix_epo_settings', 'general')
            
            if conf:
                settings['epo_server'] = conf.get('epo_server', settings['epo_server'])
                settings['epo_port'] = int(conf.get('epo_port', settings['epo_port']))
                settings['username'] = conf.get('username', settings['username'])
                settings['verify_ssl'] = str(conf.get('verify_ssl', 'true')).lower() == 'true'
                settings['use_ssl'] = str(conf.get('use_ssl', 'true')).lower() == 'true'
                settings['timeout'] = int(conf.get('timeout', settings['timeout']))
                settings['retry_attempts'] = int(conf.get('retry_attempts', settings['retry_attempts']))
                settings['batch_size'] = int(conf.get('batch_size', settings['batch_size']))
                settings['polling_interval'] = int(conf.get('polling_interval', settings['polling_interval']))
                settings['log_level'] = conf.get('log_level', settings['log_level'])
                
        except Exception as e:
            logger.warning(f"Could not load global settings: {str(e)}. Using defaults.")
        
        return settings
    
    def _collect_events(self, input_name, input_item, ew):
        """
        Collect events for a specific input
        
        Args:
            input_name: Name of the modular input
            input_item: Input configuration dictionary
            ew: EventWriter for writing events to Splunk
        """
        session_key = self._get_session_key()
        
        # Load global settings from settings conf
        global_settings = self._load_global_settings(session_key)
        
        # Parse input-specific configuration (overrides global settings)
        config = input_item
        input_type = config.get('input_type', '')
        
        # ePO connection settings (prefer input-specific, fall back to global)
        epo_url = config.get('epo_url') or global_settings['epo_server']
        epo_port = int(config.get('epo_port') or global_settings['epo_port'])
        epo_username = config.get('epo_username') or global_settings['username']
        epo_password = config.get('epo_password', '')
        epo_token = config.get('epo_token', '')
        ssl_verify = str(config.get('ssl_verify', str(global_settings['verify_ssl']))).lower() == 'true'
        
        # Collection settings
        polling_interval = int(config.get('polling_interval') or global_settings['polling_interval'])
        batch_size = int(config.get('batch_size') or global_settings['batch_size'])
        
        # Output settings
        index = config.get('index', 'main')
        sourcetype = config.get('sourcetype', f'trellix_epo:{input_type}')
        
        checkpoint_dir = config.get('checkpoint_dir', '')
        
        # Initialize authentication
        try:
            auth = TrellixEPOAuth(
                epo_url=epo_url,
                port=epo_port,
                username=epo_username,
                password=epo_password,
                token=epo_token if epo_token else None,
                ssl_verify=ssl_verify
            )
            
            # Initialize client
            client = TrellixEPOClient(auth, session_key)
            
            # Authenticate
            auth.authenticate(session_key)
            
        except Exception as e:
            error_msg = f"Failed to initialize ePO client: {str(e)}"
            logger.error(error_msg)
            ew.log(EventWriter.ERROR, error_msg)
            return
        
        # Load checkpoint
        checkpoint_file = self._get_checkpoint_file(checkpoint_dir, input_name)
        last_run_time = self._load_checkpoint(checkpoint_file)
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = last_run_time if last_run_time else (end_time - timedelta(hours=24))
        
        # Collect data based on input type
        events = []
        
        try:
            if input_type == 'threat_events':
                events = client.get_threat_events(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            elif input_type == 'malware_detections':
                events = client.get_malware_detections(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            elif input_type == 'host_status':
                events = client.get_host_status(limit=batch_size)
            elif input_type == 'agent_status':
                events = client.get_agent_status(limit=batch_size)
            elif input_type == 'policy_compliance':
                events = client.get_policy_compliance(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            elif input_type == 'quarantine_events':
                events = client.get_quarantine_events(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            elif input_type == 'updates':
                events = client.get_updates(limit=batch_size)
            elif input_type == 'user_actions':
                events = client.get_user_actions(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            # =========================================================
            # NEW v2.0.0 INPUT TYPES
            # =========================================================
            elif input_type == 'threat_summary':
                events = client.get_threat_summary(limit=batch_size)
            elif input_type == 'software_status':
                events = client.get_software_status(limit=batch_size)
            elif input_type == 'compliance_overview':
                events = client.get_compliance_overview(limit=batch_size)
            elif input_type == 'dlp_incidents':
                events = client.get_dlp_incidents(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            elif input_type == 'device_management':
                events = client.get_device_management(limit=batch_size)
            elif input_type == 'edr_events':
                events = client.get_edr_events(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            elif input_type == 'web_control_events':
                events = client.get_web_control_events(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            elif input_type == 'firewall_events':
                events = client.get_firewall_rules(limit=batch_size)
            elif input_type == 'app_control_events':
                events = client.get_app_control_events(
                    start_time=start_time,
                    end_time=end_time,
                    limit=batch_size
                )
            # =========================================================
            # END OF NEW v2.0.0 INPUT TYPES
            # =========================================================
            else:
                logger.warning(f"Unknown input type: {input_type}")
                return
            
            # Emit events
            event_count = 0
            for event_data in events:
                try:
                    event = self._create_event(
                        event_data,
                        input_type,
                        sourcetype,
                        index,
                        input_name
                    )
                    ew.write_event(event)
                    event_count += 1
                except Exception as e:
                    logger.warning(f"Failed to write event: {str(e)}")
                    continue
            
            # Save checkpoint
            self._save_checkpoint(checkpoint_file, end_time)
            
            logger.info(f"Collected {event_count} events for input {input_name} (type: {input_type})")
            
        except TrellixEPOClientError as e:
            error_msg = f"ePO API error: {str(e)}"
            logger.error(error_msg)
            ew.log(EventWriter.ERROR, error_msg)
        except Exception as e:
            error_msg = f"Unexpected error collecting events: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg)
            ew.log(EventWriter.ERROR, error_msg)
    
    def _create_event(self, event_data, input_type, sourcetype, index, input_name):
        """
        Create Splunk event from event data
        
        Args:
            event_data: Event data dictionary
            input_type: Type of input
            sourcetype: Sourcetype for event
            index: Index for event
            input_name: Name of input
            
        Returns:
            Event object
        """
        # Convert to JSON string
        if isinstance(event_data, dict):
            # Add metadata
            event_data['input_type'] = input_type
            event_data['input_name'] = input_name
            event_data['epo_source'] = 'trellix_epo'
            
            # Extract timestamp if available
            timestamp = None
            for time_field in ['detectedUTC', 'timestampUTC', 'quarantinedUTC', 
                             'lastUpdateTime', 'lastCommunicationTime', 'checkedUTC', '_time']:
                if time_field in event_data:
                    try:
                        time_value = event_data[time_field]
                        if isinstance(time_value, str):
                            # Try to parse ISO format
                            timestamp = datetime.fromisoformat(time_value.replace('Z', '+00:00'))
                        elif isinstance(time_value, (int, float)):
                            timestamp = datetime.fromtimestamp(time_value)
                        break
                    except (ValueError, TypeError, AttributeError) as parse_error:
                        logger.debug(f"Could not parse timestamp from {time_field}: {parse_error}")
                        continue
            
            # Create event
            event_json = json.dumps(event_data, default=str)
            
            event = Event()
            event.data = event_json
            event.sourcetype = sourcetype
            event.index = index
            
            if timestamp:
                event.time = timestamp.timestamp()
            else:
                event.time = time.time()
            
            return event
        else:
            # Fallback for non-dict data
            event = Event()
            event.data = str(event_data)
            event.sourcetype = sourcetype
            event.index = index
            event.time = time.time()
            return event
    
    def _get_session_key(self):
        """
        Get Splunk session key from input XML.
        
        For modular inputs, Splunk passes configuration via stdin as XML.
        The session_key is embedded in this XML structure.
        
        Returns:
            Session key string or None if not available
        """
        try:
            # Try to get from environment first
            session_key = os.environ.get('SPLUNK_SESSION_KEY')
            if session_key:
                return session_key
            
            # For modular inputs, session key comes from the parent Script class
            # Try to access it from the input definition
            if hasattr(self, '_input_definition') and self._input_definition:
                if hasattr(self._input_definition, 'metadata'):
                    return self._input_definition.metadata.get('session_key')
            
            # Fallback: parse from stdin if needed (for standalone testing)
            # Note: stdin is already consumed by splunklib during normal operation
            return None
            
        except Exception as e:
            logger.warning(f"Could not get session key: {str(e)}")
            return None
    
    def _get_checkpoint_file(self, checkpoint_dir, input_name):
        """Get checkpoint file path"""
        if not checkpoint_dir:
            # Use default checkpoint location
            checkpoint_dir = os.path.join(
                os.path.expanduser('~'),
                '.splunk',
                'checkpoints',
                'TA-trellix-epo'
            )
        
        # Create directory if it doesn't exist
        os.makedirs(checkpoint_dir, exist_ok=True)
        
        # Sanitize input name for filename
        safe_name = "".join(c for c in input_name if c.isalnum() or c in ('-', '_'))
        return os.path.join(checkpoint_dir, f"{safe_name}.checkpoint")
    
    def _load_checkpoint(self, checkpoint_file):
        """Load last run time from checkpoint"""
        if not os.path.exists(checkpoint_file):
            return None
        
        try:
            with open(checkpoint_file, 'r') as f:
                checkpoint_data = json.load(f)
                last_time_str = checkpoint_data.get('last_run_time')
                if last_time_str:
                    return datetime.fromisoformat(last_time_str)
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {str(e)}")
        
        return None
    
    def _save_checkpoint(self, checkpoint_file, run_time):
        """Save checkpoint with last run time"""
        try:
            checkpoint_data = {
                'last_run_time': run_time.isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            with open(checkpoint_file, 'w') as f:
                json.dump(checkpoint_data, f)
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {str(e)}")


def main():
    """Main entry point"""
    if not SPLUNKLIB_AVAILABLE:
        logger.error("splunklib is not available. Cannot run modular input.")
        print("ERROR: splunklib is not available. Please ensure Splunk is properly installed.", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Run the modular input
        sys.exit(TrellixEPOInput().run(sys.argv))
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}\n{traceback.format_exc()}")
        sys.exit(1)


if __name__ == "__main__":
    main()

