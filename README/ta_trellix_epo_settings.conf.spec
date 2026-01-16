# Trellix ePO Add-on Settings Configuration Specification
# This file describes the format of ta_trellix_epo_settings.conf

[general]
# ePO Server URL (hostname or IP address, without protocol)
# Required. Example: epo.example.com
epo_server = <string>

# ePO Server Port
# Default: 8443
epo_port = <integer>

# Use SSL/TLS for connections
# Default: true
use_ssl = <boolean>

# Verify SSL certificates
# Set to false only for self-signed certificates in test environments
# Default: true
verify_ssl = <boolean>

# ePO username for authentication
# The password should be stored using the configure_credentials.py script
username = <string>

# Request timeout in seconds
# Default: 60
timeout = <integer>

# Number of retry attempts for failed requests
# Default: 3
retry_attempts = <integer>

# Default batch size for API requests
# Default: 1000
batch_size = <integer>

# Default polling interval in seconds
# Default: 300 (5 minutes)
polling_interval = <integer>

# Enable incremental collection using checkpoints
# Default: true
incremental_collection = <boolean>

# Log level for debugging
# Valid values: DEBUG, INFO, WARNING, ERROR
# Default: INFO
log_level = DEBUG|INFO|WARNING|ERROR


[proxy]
# Enable proxy for ePO connections
# Default: false
use_proxy = <boolean>

# Proxy server address
proxy_server = <string>

# Proxy server port
proxy_port = <integer>

# Proxy username (if authentication required)
proxy_username = <string>

# Proxy password (if authentication required)
proxy_password = <string>