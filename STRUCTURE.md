# Trellix ePO Splunk Add-on - Complete File Structure

```
TA-trellix-epo/
│
├── app.manifest                          # App manifest metadata
├── README.md                             # Comprehensive documentation
├── requirements.txt                      # Python dependencies
├── .gitignore                           # Git ignore patterns
│
├── bin/                                  # Python scripts directory
│   ├── trellix_epo_input.py            # Main modular input (Splunk entry point)
│   ├── trellix_epo_client.py           # REST API client for ePO
│   ├── trellix_epo_auth.py             # Authentication handler
│   └── utils/                           # Utility functions
│       └── __init__.py                  # Utils package init
│
├── default/                              # Default configuration directory
│   ├── app.conf                         # App configuration
│   ├── inputs.conf                      # Input definitions template
│   ├── props.conf                       # Field extractions and sourcetypes
│   ├── transforms.conf                  # CIM normalization transforms
│   ├── restmap.conf                     # REST endpoint mappings
│   │
│   └── data/                            # UI and view data
│       └── ui/
│           ├── setup.xml                # Setup/configuration UI
│           ├── nav/
│           │   └── default.xml          # Navigation menu configuration
│           └── views/
│               └── trellix_epo_overview.xml  # Main all-in-one dashboard
│
└── metadata/                             # Metadata directory
    └── default.meta                      # Permissions and metadata

```

## File Count Summary

- **Python Scripts**: 4 files (3 main + 1 utils)
- **Configuration Files**: 5 files
- **XML Files**: 3 files (setup, navigation, dashboard)
- **Documentation**: 2 files (README, STRUCTURE)
- **Metadata**: 2 files (manifest, meta)
- **Total**: 17 files

## Key Components

### Core Python Modules
1. **trellix_epo_input.py** - Splunk modular input that orchestrates data collection
2. **trellix_epo_client.py** - Handles all REST API interactions with ePO
3. **trellix_epo_auth.py** - Manages secure authentication and credential storage

### Configuration
1. **app.conf** - Defines app metadata and settings
2. **inputs.conf** - Input definitions (auto-configured)
3. **props.conf** - Field extractions and sourcetype definitions
4. **transforms.conf** - CIM normalization rules
5. **restmap.conf** - REST API endpoint mappings

### User Interface
1. **setup.xml** - Configuration UI for ePO connection settings
2. **trellix_epo_overview.xml** - Comprehensive security dashboard
3. **default.xml** - Navigation menu configuration

## Installation Instructions

1. Copy entire `TA-trellix-epo` directory to `$SPLUNK_HOME/etc/apps/`
2. Set executable permissions on Python files (Unix/Linux):
   ```bash
   chmod +x $SPLUNK_HOME/etc/apps/TA-trellix-epo/bin/*.py
   ```
3. Restart Splunk
4. Configure via Setup UI in Splunk Web
5. Create data inputs for desired data sources

## Quick Start

1. **Install**: Copy to Splunk apps directory
2. **Configure**: Navigate to Apps → Trellix ePO Add-on → Set up
3. **Setup**: Enter ePO connection details
4. **Create Inputs**: Configure data collection inputs
5. **View Dashboard**: Access "Trellix ePO Security Overview"

## Data Sources Supported

✅ Threat Events  
✅ Malware Detections  
✅ Host Status  
✅ Agent Status  
✅ Policy Compliance  
✅ Quarantine Events  
✅ Updates/DAT Versions  
✅ User Actions  

All data sources are CIM-compliant and ready for Enterprise Security (ES) integration.

