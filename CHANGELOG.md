# Changelog

All notable changes to the **TA-Trellix-EPO Add-on** will be documented in this file.

📦 **Splunkbase**: [https://splunkbase.splunk.com/app/8351](https://splunkbase.splunk.com/app/8351)  
📖 **GitHub**: [https://github.com/sarat1kyan/TA-trellix-epo](https://github.com/sarat1kyan/TA-trellix-epo)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] - 2026-01-16

### Changed
- **Dashboard: Theme changed to light** - Switched from dark to light theme for better readability
- **Dashboard: Reorganized Executive Summary** - Now shows only metrics with actual data:
  - Total Managed Endpoints
  - Windows Endpoints  
  - Linux Endpoints
  - Managed Agents
  - Events Ingested (24h)

### Fixed
- **Dashboard: timechart span=auto errors** - Changed all `span=auto` to `span=1h` in dashboard queries
- **Dashboard: Field name mismatches** - Updated all queries to use actual ePO field names:
  - `EPOComputerProperties.ComputerName` for hostname
  - `EPOComputerProperties.IPAddress` for IP
  - `EPOComputerProperties.OSType` for OS
  - `EPOLeafNode.AgentVersion` for agent version
  - `EPOLeafNode.ManagedState` for agent status (1=Managed, 0=Unmanaged)
- **Dashboard: Agent Status showing "Unknown"** - Now derives status from `EPOLeafNode.ManagedState`
- **Dashboard: DAT Version showing timestamps** - Renamed to "Agent Version Distribution"

### Added
- **Data Source Status Panel** - Explains which inputs need to be enabled for each section
- **Section notices** - Each section (Threat Intelligence, Policy Compliance, User Activity, Advanced Analytics) now shows a notice explaining which inputs are required
- **Endpoint Inventory table** - Shows hostname, IP, OS, domain, user, agent version, and last update
- **Critical: Authentication method** - Changed from token-based to basic auth for all API requests
  - Trellix ePO requires username:password basic auth on every request, not token-based auth
  - Now uses `requests.auth.HTTPBasicAuth` directly instead of manual Authorization headers
  - Removed token refresh logic that was causing 401 errors after initial authentication
- Successfully tested with 201 hosts retrieved from production ePO server

---

## [1.2.1] - 2026-01-15

### Fixed
- **threat_events/malware_detections** - Auto-discovers threat-related saved queries
- **policy_compliance** - Uses query ID 4 ("Policy Assignment Change History") as default
- **user_actions** - Searches for audit queries targeting OrionAuditLog

---

## [1.2.0] - 2026-01-15

### Changed
- **Major API Rewrite** - Updated to work with actual Trellix ePO API structure
  - ePO returns text format with `OK:` prefix, not JSON - added `_parse_text_response()`
  - Field names have spaces (e.g., "System Name" not "computerName") - added `FIELD_MAPPINGS`
  - Added `_normalize_record()` to convert ePO field names to CIM-compatible names
  - Threat/malware/audit data uses saved queries via `core.executeQuery`
  - Host/agent status uses `system.find` command

### Added
- **New API Methods**
  - `get_available_queries()` - List all saved queries in ePO
  - `execute_query(query_id)` - Execute a saved query by ID
  - `_parse_query_list()` - Parse `core.listQueries` text response
  - `_parse_text_response()` - Parse ePO text format into list of dicts
  - `_normalize_record()` - Normalize field names using FIELD_MAPPINGS

### Fixed
- **API Compatibility** - Now works with actual ePO API structure discovered from user's server
- **host_status** - Uses `system.find` which returns actual system data
- **agent_status** - Uses `system.find` and derives status from Last Communication field

---

## [1.1.9] - 2026-01-15

### Fixed
- **Production Audit Fixes** - Comprehensive code quality improvements
  - Fixed bare `except:` clauses in `trellix_epo_client.py` and `configure_credentials.py`
  - Fixed `timezone.utc` reference in `utils/__init__.py` (was undefined in fallback path)
  - Added `SPLUNKLIB_AVAILABLE` check in `main()` function before running modular input
  - Fixed empty stanza `[]` in `default.meta` to proper `[default]` stanza

---

## [1.1.8] - 2026-01-15

### Fixed
- **Critical: Reserved Argument Error** - Removed `index` and `sourcetype` from modular input scheme
  - These are reserved internal Splunk arguments that cannot be defined via introspection
  - Fixed "Endpoint argument 'index' is an internal argument that is handled specially within Splunk"
  - These parameters are still configurable in `inputs.conf` (handled automatically by Splunk)

---

## [1.1.7] - 2026-01-15

### Fixed
- **Critical: Modular Input Initialization** - Fixed "NameError: name 'Script' is not defined"
  - Added dynamic splunklib discovery across installed Splunk apps
  - `splunklib` is not bundled with Splunk core - searches apps like `splunk_rapid_diag`, etc.
  - Ensures `splunklib`, `requests`, and `urllib3` modules are found
  - Applied to all Python modules: `trellix_epo.py`, `trellix_epo_input.py`, `trellix_epo_client.py`, `trellix_epo_auth.py`
- **Offline Splunk Servers** - No external internet required; uses Splunk's bundled Python libraries

---

## [1.1.5] - 2026-01-14

### Fixed
- **Splunk Cloud Vetting** - Added `[trellix_epo]` modular input type stanza with python.version
  - The modular input type definition stanza is required in addition to instance stanzas
  - Fixed "python.version is not specified for modular input trellix_epo" vetting error
- **transforms.conf** - Fixed invalid multi-REGEX/FORMAT patterns (only one pair per stanza is valid)
- **trellix_epo_auth.py** - Added graceful fallback when splunklib is not available
- **ta_trellix_epo_rh_settings.py** - Added cross-platform SPLUNK_HOME detection for Windows
- **ta_trellix_epo_rh_inputs.py** - Fixed potential IndexError in argument handling
- **trellix_epo.py/trellix_epo_input.py** - Replaced bare except clause with specific exceptions

### Changed
- **inputs.conf.spec** - Added modular input type stanza documentation

---

## [1.1.4] - 2026-01-14

### Added

#### Splunk Cloud Compatibility
- **python.version = python3** - Added to each input stanza for Cloud compatibility
- **Updated inputs.conf.spec** - Full specification with python.version documentation
- **Priority labels** - Added HIGH/MEDIUM/LOW priority indicators for each input type

#### Enhanced Setup Experience
- **Quick Start Wizard** - Beautiful 3-step visual guide
- **Collapsible sections** - Advanced options hidden by default
- **Troubleshooting FAQ** - Common issues and solutions
- **Copy-ready commands** - Linux/macOS and Windows examples

#### Enhanced Documentation
- Improved inline comments in all configuration files
- Better setup instructions with step-by-step guidance

### Fixed
- **Splunkbase Cloud Vetting** - Fixed "python.version is not specified for modular input" error
- **Removed [default] stanza** - Cloud vetting doesn't allow global stanzas, moved python.version to each input
- **Modular input registration** - trellix_epo.py script now properly named for Splunk

### Changed
- **inputs.conf** - python.version added to each individual input stanza
- **inputs.conf.spec** - Removed [default] stanza, added interval documentation
- **setup_page.xml** - Complete redesign with Quick Start wizard
- **File structure** - 8 Python scripts (added trellix_epo.py entry point)

---

## [1.1.3] - 2026-01-14

### Fixed

#### Modular Input Registration
- **Added trellix_epo.py** - Script name must match modular input scheme name
  - Fixes "Unable to initialize modular input" error
  - Splunk requires script name to match the scheme (trellix_epo:// → trellix_epo.py)

#### Credential Configuration Script
- **configure_credentials.py** - Fixed "No session key available" error
  - Script now prompts for Splunk admin credentials to authenticate
  - Uses splunklib instead of trying to read session key from stdin
  - Added password confirmation step
  - Added curl alternative for users without splunklib
- **setup_page.xml** - Updated credential configuration instructions with both script and curl methods
- **requirements.txt** - Added splunk-sdk as a dependency

---

## [1.1.2] - 2026-01-13

### Added

#### New Dashboard-Based Setup Page
- **setup_page.xml** - Beautiful, comprehensive configuration guide dashboard
  - Step-by-step setup instructions with code examples
  - Configuration parameter reference tables
  - Secure credential storage guide
  - Data input configuration documentation
  - Quick links to manage inputs, view dashboard, and documentation
  - Modern dark theme with professional styling

### Changed
- **app.conf** - Updated `setup_view = setup_page` to point to new dashboard view
- **default.xml** (navigation) - Added "Setup Guide" link to Configuration menu
- **Removed legacy setup.xml** - Replaced with modern dashboard-based approach

### Fixed
- **404 error on Setup page** - The previous fix removed `setup_view` entirely, which also removed the setup button
- **Navigation "Configure Settings" 404** - Was linking to `/app/TA-trellix-epo/setup` which didn't exist
- **App Manager Setup button** - Now properly opens the setup_page dashboard

---

## [1.1.1] - 2026-01-13

### Fixed

#### Setup Page 404 Error
- **Removed `setup_view = setup`** from `app.conf` - This was pointing to a non-existent dashboard view instead of using the legacy setup.xml
- **Fixed setup.xml endpoint paths** - Changed endpoints from `ta_trellix_epo/ta_trellix_epo_settings/general` to `admin/ta_trellix_epo/ta_trellix_epo_settings` to match the restmap.conf admin handler registration
- **Fixed setup.xml input types** - Changed `checkbox` to `bool` and `dropdown` to `list` per Splunk's setup.xml schema
- **Updated REST handler** - Added all missing fields (use_ssl, polling_interval, batch_size, retry_attempts, proxy settings) to support the complete setup form

#### REST API Configuration
- **Fixed restmap.conf** - Changed `handlerpersistent` to `handlerpersistentmode` per Splunk's current schema
- **Enhanced metadata permissions** - Added proper export and access permissions for admin handlers

### Changed
- **ta_trellix_epo_rh_settings.py** - Refactored to support all configuration fields with proper default values
- **default.meta** - Updated permissions for admin_external handlers

---

## [1.1.0] - 2026-01-13

### Added

#### CIM Compliance
- **eventtypes.conf** - 15+ event types for comprehensive data categorization
  - `trellix_epo_malware` / `trellix_epo_malware_attack` for malware events
  - `trellix_epo_ids` / `trellix_epo_ids_attack` for intrusion detection
  - `trellix_epo_endpoint` / `trellix_epo_endpoint_services` for endpoint data
  - `trellix_epo_change` / `trellix_epo_change_audit` for policy changes
  - `trellix_epo_authentication` / `trellix_epo_authentication_failure` for auth events
  - `trellix_epo_audit` / `trellix_epo_audit_admin` for user activity
  - `trellix_epo_quarantine` for quarantine events
  - `trellix_epo_syslog_threat` for syslog-based threat data

- **tags.conf** - Full CIM data model tagging
  - Malware data model tags
  - Intrusion_Detection data model tags
  - Endpoint data model tags
  - Change data model tags
  - Authentication data model tags
  - Audit trail tags

#### Dashboard Enhancements
- **Security Command Center** - Complete dashboard redesign
  - Executive summary row with key metrics
  - Color-coded severity indicators (Critical/High/Medium/Low)
  - Interactive drilldowns on all visualizations
  - Threat event timeline with stacked area charts
  - IOC hunt panel for file hashes
  - Endpoint protection status section
  - Policy compliance tracking dashboard
  - User activity monitoring
  - Advanced analytics with day/hour heatmap
  - Quarantine actions timeline

#### Styling
- **Custom CSS** (`appserver/static/trellix_epo_dashboard.css`)
  - Dark theme with GitHub-inspired color palette
  - Glassmorphism panel effects with hover animations
  - Custom scrollbar styling
  - Severity color classes
  - Enhanced table styling with row highlighting
  - Smooth fade-in animations

#### Utilities
- **utils/__init__.py** - New utility module
  - `parse_boolean()` - Parse various boolean representations
  - `parse_integer()` - Safe integer parsing with defaults
  - `format_timestamp()` - Timestamp formatting
  - `safe_json_loads()` - Safe JSON parsing
  - `sanitize_string()` - String sanitization for logging
  - `mask_sensitive_data()` - Mask sensitive fields for secure logging
  - `EventNormalizer` class - Field normalization utility

#### Configuration
- **inputs.conf.spec** - Complete input configuration specification
- Enhanced navigation menu with configuration links and resources

### Changed

#### Python Modules
- **trellix_epo_input.py**
  - Added global settings loading from `ta_trellix_epo_settings.conf`
  - Improved session key handling for modular inputs
  - Better error messages and logging format
  - Support for input-specific configuration overrides

- **trellix_epo_client.py**
  - Added `API_COMMANDS` dictionary for command mapping
  - Enhanced error handling with `TrellixEPOClientError` including status codes
  - Implemented `_parse_epo_response()` for handling ePO's `OK:` prefix format
  - Added `_normalize_events()` for consistent field naming
  - Added `_normalize_time_param()` for date/time handling
  - Implemented `test_connection()` method
  - Configurable timeout and retry attempts
  - Enhanced rate limiting with configurable backoff
  - Exponential backoff for server errors
  - Comprehensive docstrings for all public methods

#### Configuration Files
- **local/inputs.conf**
  - Consistent sourcetype naming (`trellix_epo:<type>`)
  - Added `input_type` parameter for all inputs
  - Optimized polling intervals (300s-14400s based on data priority)
  - Enabled all data inputs by default

- **local/ta_trellix_epo_settings.conf**
  - Added comprehensive configuration sections
  - Added proxy settings section
  - Better documentation comments

- **default/app.conf**
  - Version bump to 1.1.0
  - Added setup_view reference
  - Enhanced description
  - Added trigger reloads for eventtypes and tags

- **app.manifest**
  - Updated to schema version 2.0.0
  - Added CIM data model declarations
  - Updated release notes
  - Added platform requirements

#### User Interface
- **setup.xml** - Reorganized into logical configuration blocks
- **nav/default.xml** - Added configuration and resource links

### Fixed
- Sourcetype inconsistencies between `local/inputs.conf` and `props.conf`
- Session key handling in modular input module
- Response parsing for ePO API's `OK:` prefix format

### Security
- Enhanced credential masking in logs
- Improved secure credential storage documentation

---

## [1.0.0] - 2024-01-01

### Added
- Initial release
- Support for all major ePO data sources:
  - Threat Events
  - Malware Detections
  - Host Status
  - Agent Status
  - Policy Compliance
  - Quarantine Events
  - Updates/DAT Versions
  - User Actions
- CIM normalization via props.conf and transforms.conf
- Basic security dashboard (trellix_epo_overview.xml)
- Syslog threat events dashboard
- Setup UI for configuration
- REST handlers for settings and inputs
- Secure credential storage support
- SSL/TLS verification (configurable)
- Checkpoint-based incremental collection
- Rate limiting and retry logic
- Connection pooling with session management

---

## Version Comparison

| Feature | v1.0.0 | v1.1.0 |
|---------|--------|--------|
| CIM eventtypes | ❌ | ✅ |
| CIM tags | ❌ | ✅ |
| Custom CSS | ❌ | ✅ |
| Interactive drilldowns | Limited | ✅ Full |
| Utils module | ❌ | ✅ |
| Test connection method | ❌ | ✅ |
| Enhanced error handling | Basic | ✅ Advanced |
| Spec files | Partial | ✅ Complete |
| Event normalization | Manual | ✅ Automatic |

---

## Upgrade Notes

### From v1.0.0 to v1.1.0

1. **Backup your local configuration:**
   ```bash
   cp -r $SPLUNK_HOME/etc/apps/TA-trellix-epo/local /tmp/ta-trellix-epo-backup
   ```

2. **Install the new version:**
   - Replace the app directory with the new version
   - Restore your `local/ta_trellix_epo_settings.conf` if needed

3. **Clear your browser cache** to see the new CSS styling

4. **Restart Splunk:**
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ```

5. **Rebuild CIM acceleration** (if using Enterprise Security):
   - Navigate to Settings → Data models
   - Rebuild acceleration for affected data models

---

[1.1.7]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.1.7
[1.1.5]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.1.5
[1.1.4]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.1.4
[1.1.3]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.1.3
[1.1.2]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.1.2
[1.1.1]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.1.1
[1.1.0]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.1.0
[1.0.0]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.0.0
