# Trellix ePO Input Configuration Specification
# This file describes the format of trellix_epo input configurations

# Modular Input Type Definition
# Required for Splunk Cloud compatibility
[trellix_epo]
python.version = <string>
* Python version for modular input execution
* Required for Splunk Cloud compatibility
* Valid values: python3, python3.7, python3.9

# Individual Input Instance Definitions
[trellix_epo://<name>]
# Python version for modular input execution
# Required for Splunk Cloud compatibility
# Valid values: python3, python3.7, python3.9
python.version = <string>

# Input type - determines what data to collect from ePO
# Valid values (v1.x - Core):
#   threat_events, malware_detections, host_status, agent_status,
#   policy_compliance, quarantine_events, updates, user_actions
# Valid values (v2.0 - Enterprise):
#   threat_summary, software_status, compliance_overview, dlp_incidents,
#   device_management, edr_events, web_control_events, firewall_events,
#   app_control_events
input_type = <string>

# Override ePO server URL for this specific input
# If not set, uses value from ta_trellix_epo_settings.conf
epo_url = <string>

# Override ePO server port for this specific input
# If not set, uses value from ta_trellix_epo_settings.conf
epo_port = <integer>

# Override ePO username for this specific input
# If not set, uses value from ta_trellix_epo_settings.conf
epo_username = <string>

# ePO password (stored securely via configure_credentials.py)
epo_password = <string>

# Pre-existing ePO authentication token (optional)
epo_token = <string>

# Verify SSL certificates for this input
# If not set, uses value from ta_trellix_epo_settings.conf
ssl_verify = <boolean>

# Polling interval in seconds (how often to collect data)
# Default: 300 (5 minutes)
# Recommended: 300-600 for threat events, 3600-14400 for host status
polling_interval = <integer>

# Maximum events to retrieve per poll
# Default: 1000
batch_size = <integer>

# Target Splunk index
# Default: main
index = <string>

# Sourcetype for events
# Default: trellix_epo:<input_type>
sourcetype = <string>

# Custom checkpoint directory
# Default: $SPLUNK_HOME/var/lib/splunk/modinputs/trellix_epo
checkpoint_dir = <string>

# Whether input is disabled
# Default: 1 (disabled) - set to 0 to enable
disabled = 0|1

# Collection interval in seconds
# This is the standard Splunk interval parameter
interval = <integer>
