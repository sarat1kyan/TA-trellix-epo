#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Trellix ePO Modular Input for Splunk
Main entry point for data collection from Trellix ePO REST API
"""

import sys
import os
import json
import logging
import time
import traceback
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

# Add lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Splunk libraries
from splunklib.modularinput import Script, Scheme, Argument, EventWriter
from splunklib.modularinput.event import Event, XMLEventWriter
from splunklib.binding import connect

# Import our modules
try:
    from trellix_epo_auth import TrellixEPOAuth, TrellixEPOAuthError
    from trellix_epo_client import TrellixEPOClient, TrellixEPOClientError
except ImportError as e:
    logging.error(f"Failed to import modules: {str(e)}")
    raise

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)


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
        
        # Index configuration
        scheme.add_argument(Argument(
            "index",
            title="Index",
            description="Splunk index to write events to",
            required_on_create=False
        ))
        
        scheme.add_argument(Argument(
            "sourcetype",
            title="Sourcetype",
            description="Sourcetype for events",
            required_on_create=False
        ))
        
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
    
    def _collect_events(self, input_name, input_item, ew):
        """Collect events for a specific input"""
        
        # Parse configuration
        config = input_item
        input_type = config.get('input_type', '')
        epo_url = config.get('epo_url', '')
        epo_port = int(config.get('epo_port', 8443))
        epo_username = config.get('epo_username', '')
        epo_password = config.get('epo_password', '')
        epo_token = config.get('epo_token', '')
        ssl_verify = str(config.get('ssl_verify', 'true')).lower() == 'true'
        
        polling_interval = int(config.get('polling_interval', 300))  # Default 5 minutes
        batch_size = int(config.get('batch_size', 1000))
        
        index = config.get('index', 'main')
        sourcetype = config.get('sourcetype', f'trellix_epo:{input_type}')
        
        checkpoint_dir = config.get('checkpoint_dir', '')
        session_key = self._get_session_key()
        
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
                    except:
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
        """Get Splunk session key"""
        try:
            # Try to get from environment
            session_key = os.environ.get('SPLUNK_SESSION_KEY')
            if session_key:
                return session_key
            
            # Try to read from stdin (for modular inputs)
            return sys.stdin.read()
        except:
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
    try:
        # Run the modular input
        sys.exit(TrellixEPOInput().run(sys.argv))
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}\n{traceback.format_exc()}")
        sys.exit(1)


if __name__ == "__main__":
    main()

