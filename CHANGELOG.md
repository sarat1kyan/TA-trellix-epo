# Changelog

All notable changes to the **TA-Trellix-EPO Add-on** will be documented in this file.

📦 **Splunkbase**: [https://splunkbase.splunk.com/app/8351](https://splunkbase.splunk.com/app/8351)  
📖 **GitHub**: [https://github.com/sarat1kyan/TA-trellix-epo](https://github.com/sarat1kyan/TA-trellix-epo)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.1.0
[1.0.0]: https://github.com/sarat1kyan/TA-trellix-epo/releases/tag/v1.0.0
