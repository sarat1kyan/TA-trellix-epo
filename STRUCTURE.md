# Trellix ePO Splunk Add-on - Complete File Structure

```
TA-trellix-epo/
│
├── app.manifest                          # App manifest metadata (v1.1.2)
├── CHANGELOG.md                          # Version history and release notes
├── README.md                             # Comprehensive documentation
├── STRUCTURE.md                          # This file
├── requirements.txt                      # Python dependencies
│
├── bin/                                  # Python scripts directory
│   ├── trellix_epo_input.py             # Main modular input (Splunk entry point)
│   ├── trellix_epo_client.py            # REST API client for ePO
│   ├── trellix_epo_auth.py              # Authentication handler
│   ├── configure_credentials.py          # Credential storage utility
│   ├── ta_trellix_epo_rh_settings.py    # REST handler for settings
│   ├── ta_trellix_epo_rh_inputs.py      # REST handler for inputs
│   └── utils/                            # Utility functions
│       └── __init__.py                   # Utils package with helpers
│
├── default/                              # Default configuration directory
│   ├── app.conf                          # App configuration
│   ├── inputs.conf                       # Input definitions (disabled by default)
│   ├── ta_trellix_epo_settings.conf      # ePO server connection settings
│   ├── props.conf                        # Field extractions and sourcetypes
│   ├── transforms.conf                   # CIM normalization transforms
│   ├── restmap.conf                      # REST endpoint mappings
│   ├── eventtypes.conf                   # Event type definitions for CIM
│   ├── tags.conf                         # Tag definitions for CIM data models
│   │
│   └── data/                             # UI and view data
│       └── ui/
│           ├── nav/
│           │   └── default.xml           # Navigation menu configuration
│           └── views/
│               ├── setup_page.xml                 # Setup/configuration guide dashboard
│               ├── trellix_epo_overview.xml       # Security Command Center
│               └── trellix_epo_syslog_threats.xml # Syslog threat dashboard
│
│
├── appserver/                            # Application server assets
│   └── static/
│       └── trellix_epo_dashboard.css     # Custom dashboard styling
│
├── static/                               # Static assets
│   └── appIcon.png                       # App icon
│
├── metadata/                             # Metadata directory
│   └── default.meta                      # Permissions and metadata
│
└── README/                               # Spec files
    ├── ta_trellix_epo_settings.conf.spec # Settings configuration spec
    └── inputs.conf.spec                  # Input configuration spec
```

## File Count Summary

- **Python Scripts**: 7 files (3 main + 2 REST handlers + 1 utility + 1 credential tool)
- **Configuration Files**: 8 files (app, inputs, settings, props, transforms, restmap, eventtypes, tags)
- **XML Files**: 4 files (navigation, 3 dashboards including setup)
- **CSS Files**: 1 file (custom dashboard styling)
- **Documentation**: 3 files (README, STRUCTURE, CHANGELOG)
- **Spec Files**: 2 files (settings spec, inputs spec)
- **Metadata**: 2 files (manifest, meta)
- **Total**: ~26 files

## Key Features

### Data Collection (v1.1.0)
✅ Threat Events - Real-time threat detection events  
✅ Malware Detections - Malware identification and details  
✅ Host Status - System health and status information  
✅ Agent Status - ePO agent connectivity and versions  
✅ Policy Compliance - Policy violations and compliance status  
✅ Quarantine Events - Quarantine actions and file information  
✅ Updates/DAT Versions - DAT update status and versions  
✅ User Actions - Audit logs for user activities  

### CIM Compliance
✅ Full eventtypes.conf for event classification  
✅ Full tags.conf for CIM data model mapping  
✅ Intrusion_Detection data model  
✅ Malware data model  
✅ Endpoint data model  
✅ Change data model  
✅ Authentication data model  

### Dashboards
✅ Security Command Center - Comprehensive threat overview  
✅ Syslog Threat Events - For syslog-based threat data  
✅ Interactive drilldowns  
✅ Custom CSS styling  
✅ Dark theme with GitHub-inspired colors  

### Security Features
✅ Encrypted credential storage  
✅ Token-based and basic authentication  
✅ SSL/TLS verification (configurable)  
✅ Proxy support  
✅ Rate limiting protection  
✅ Automatic retry with exponential backoff  

## Installation

### Option 1: Splunkbase (Recommended)
1. Visit [https://splunkbase.splunk.com/app/8351](https://splunkbase.splunk.com/app/8351)
2. Click **Download** or install via Splunk Web: Apps → Find More Apps → "Trellix ePO"
3. Restart Splunk if prompted

### Option 2: Manual Installation
1. Copy `TA-trellix-epo` directory to `$SPLUNK_HOME/etc/apps/`
2. Set executable permissions (Linux/macOS):
   ```bash
   chmod +x $SPLUNK_HOME/etc/apps/TA-trellix-epo/bin/*.py
   ```
3. Restart Splunk

### Post-Installation
1. Configure via Setup UI: Apps → Trellix ePO Add-on → Set up
2. Store credentials securely:
   ```bash
   $SPLUNK_HOME/bin/splunk cmd python $SPLUNK_HOME/etc/apps/TA-trellix-epo/bin/configure_credentials.py
   ```
3. Enable data inputs as needed
4. Access the Security Command Center dashboard

## Supported Data Sources

| Input Type | Sourcetype | CIM Data Model | Recommended Interval |
|------------|------------|----------------|---------------------|
| threat_events | trellix_epo:threat_events | Intrusion_Detection | 300s (5min) |
| malware_detections | trellix_epo:malware_detections | Malware | 300s (5min) |
| host_status | trellix_epo:host_status | Endpoint | 3600s (1hr) |
| agent_status | trellix_epo:agent_status | Endpoint | 3600s (1hr) |
| policy_compliance | trellix_epo:policy_compliance | Change | 7200s (2hr) |
| quarantine_events | trellix_epo:quarantine_events | Malware | 600s (10min) |
| updates | trellix_epo:updates | Endpoint | 14400s (4hr) |
| user_actions | trellix_epo:user_actions | Authentication | 600s (10min) |
