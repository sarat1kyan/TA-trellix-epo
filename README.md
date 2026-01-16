<div align="center">

# Trellix (McAfee) ePO Splunk Technology Add-on

[![Splunkbase](https://img.shields.io/badge/Splunkbase-Trellix%20ePO%20All%20in%20One-green?logo=splunk)](https://splunkbase.splunk.com/app/8351)
[![Version](https://img.shields.io/badge/Version-1.1.4-blue)](https://github.com/sarat1kyan/TA-trellix-epo/releases)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![CIM](https://img.shields.io/badge/CIM-4.x%20|%205.x%20|%206.x-orange)](https://docs.splunk.com/Documentation/CIM)

<img width="1536" height="1024" alt="IMG_0189" src="https://github.com/user-attachments/assets/a6336c60-7846-489d-8d57-c4fff8487cc4" />

Non official Splunk Technology Add-on for integrating Trellix (McAfee) ePO security telemetry into Splunk. This add-on provides comprehensive data collection, CIM normalization, and a powerful all-in-one security dashboard.

**🚀 [Download from Splunkbase](https://splunkbase.splunk.com/app/8351)** | **📖 [Documentation](#overview)** | **🐛 [Report Issue](https://github.com/sarat1kyan/TA-trellix-epo/issues)**

</div>

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Data Sources](#data-sources)
- [CIM Compliance](#cim-compliance)
- [Dashboard](#dashboard)
- [API Permissions](#api-permissions)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)
- [Security](#security)
- [Support](#support)

## 🎯 Overview

The Trellix ePO Technology Add-on enables Splunk to collect, normalize, and visualize security telemetry from Trellix (formerly McAfee) ePolicy Orchestrator (ePO). It provides:

- **Comprehensive Data Collection**: Ingests threat events, malware detections, host status, agent information, policy compliance, quarantine events, updates, and user actions
- **CIM Normalization**: Automatically normalizes events to Splunk Common Information Model (CIM) for consistent security analysis
- **Enterprise-Ready**: Production-grade implementation with error handling, checkpoints, rate limiting, and secure credential storage
- **All-in-One Dashboard**: Single comprehensive dashboard with security overview, endpoint health, threat intelligence, compliance monitoring, and user activity tracking

## 🏗 Architecture

```
TA-trellix-epo/
├── bin/
│   ├── trellix_epo_input.py      # Main modular input (Splunk entry point)
│   ├── trellix_epo_client.py     # REST API client
│   ├── trellix_epo_auth.py       # Authentication handler
│   └── utils/                     # Utility functions
├── default/
│   ├── app.conf                   # App configuration
│   ├── inputs.conf                # Input definitions
│   ├── props.conf                 # Field extractions
│   ├── transforms.conf            # CIM normalization
│   ├── restmap.conf               # REST endpoints
│   ├── data/
│   │   └── ui/
│   │       ├── setup.xml          # Setup UI
│   │       └── views/
│   │           └── trellix_epo_overview.xml  # Main dashboard
├── README.md                      # This file
└── requirements.txt               # Python dependencies
```

### Data Flow

1. **Modular Input** (`trellix_epo_input.py`) - Splunk executes this script at configured intervals
2. **Authentication** (`trellix_epo_auth.py`) - Handles secure authentication with ePO REST API
3. **API Client** (`trellix_epo_client.py`) - Retrieves data from ePO with pagination and error handling
4. **Event Processing** - Events are parsed, enriched, and written to Splunk
5. **Normalization** (`props.conf`, `transforms.conf`) - Events are normalized to CIM
6. **Visualization** - Dashboard displays insights and analytics

## ✨ Features

### Data Collection
- ✅ Threat Events - Real-time threat detection events
- ✅ Malware Detections - Malware identification and details
- ✅ Host Status - System health and status information
- ✅ Agent Status - ePO agent connectivity and versions
- ✅ Policy Compliance - Policy violations and compliance status
- ✅ Quarantine Events - Quarantine actions and file information
- ✅ Updates/DAT Versions - DAT update status and versions
- ✅ User Actions - Audit logs for user activities

### Security & Reliability
- 🔒 Secure credential storage using Splunk's encrypted storage
- 🔒 Token-based and basic authentication support
- 🔒 SSL/TLS verification (configurable)
- 🔄 Incremental collection with checkpoints
- 🔄 Automatic retry on failures
- 🔄 Rate limiting protection
- 🔄 Connection pooling and session management

### CIM Compliance
- Normalized to Common Information Model (CIM)
- Compatible with Enterprise Security (ES) and Security Essentials
- Supports Malware, Intrusion_Detection, Endpoint, Change, Audit, and Network_Traffic data models

## 📥 Installation

### Prerequisites

- Splunk Enterprise 8.0 or higher (Python 3 support) or Splunk Cloud
- Trellix ePO server with REST API access
- ePO user account with appropriate permissions (see [API Permissions](#api-permissions))
- Network connectivity from Splunk to ePO server

### Option 1: Install from Splunkbase (Recommended)

The easiest way to install this add-on is directly from Splunkbase:

1. **Via Splunk Web UI:**
   - Navigate to **Apps → Find More Apps**
   - Search for "**Trellix ePO All in One**"
   - Click **Install** and follow the prompts
   - Or visit: [https://splunkbase.splunk.com/app/8351](https://splunkbase.splunk.com/app/8351)

2. **Via Splunk CLI:**
   ```bash
   $SPLUNK_HOME/bin/splunk install app https://splunkbase.splunk.com/app/8351/release/1.1.4/download -auth admin:password
   ```

3. **For Splunk Cloud:**
   - Go to **Apps → Browse More Apps** in Splunk Cloud
   - Search for "Trellix ePO" and install
   - Or request installation via Splunk Cloud support

### Option 2: Install from GitHub

For the latest development version or custom modifications:

1. **Download the Add-on**
   ```bash
   # Clone or download this repository
   git clone https://github.com/sarat1kyan/TA-trellix-epo.git
   cd TA-trellix-epo
   ```

2. **Install to Splunk**
   ```bash
   # Copy to Splunk apps directory (Linux/macOS)
   cp -r TA-trellix-epo $SPLUNK_HOME/etc/apps/
   
   # Or on Windows (PowerShell):
   Copy-Item -Recurse TA-trellix-epo $env:SPLUNK_HOME\etc\apps\
   
   # Or on Windows (CMD):
   xcopy /E /I TA-trellix-epo %SPLUNK_HOME%\etc\apps\TA-trellix-epo
   ```

3. **Set Permissions** (Linux/macOS only)
   ```bash
   # Set executable permissions on Python scripts
   chmod +x $SPLUNK_HOME/etc/apps/TA-trellix-epo/bin/*.py
   ```

4. **Restart Splunk**
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ```

### Post-Installation Steps

After installing via either method:

1. **Store ePO Credentials Securely:**
   ```bash
   $SPLUNK_HOME/bin/splunk cmd python $SPLUNK_HOME/etc/apps/TA-trellix-epo/bin/configure_credentials.py
   ```

2. **Configure the Add-on:**
   - Navigate to **Apps → Trellix ePO Add-on → Set up**
   - Enter your ePO server URL, port, and username

3. **Enable Data Inputs:**
   - Go to **Settings → Data Inputs → Trellix ePO Input**
   - Enable and configure the inputs you need

## ⚙️ Configuration

### Initial Setup

1. **Access Setup Page**
   - Navigate to Splunk Web
   - Go to Apps → Manage Apps → Trellix ePO Add-on → Set up

2. **Configure ePO Connection**
   - **ePO Server URL**: Hostname or IP address (e.g., `epo.example.com`)
   - **ePO Server Port**: Default `8443` for HTTPS
   - **Use SSL/TLS**: Enable for secure connections
   - **Verify SSL Certificate**: Enable unless using self-signed certificates

3. **Configure Authentication**
   - **Authentication Method**: Username/Password or Token
   - **ePO Username**: ePO user account
   - **ePO Password**: Password (stored securely)
   - **ePO Token**: Optional pre-existing token

4. **Configure Data Collection**
   - **Polling Interval**: How often to poll (default: 300 seconds)
   - **Batch Size**: Max events per poll (default: 1000)
   - **Default Index**: Target Splunk index
   - **Enable Incremental Collection**: Recommended for avoiding duplicates

5. **Test Connection**
   - Click "Test Connection" to verify settings
   - Save configuration

### Configure Data Inputs

After initial setup, configure individual data inputs:

1. Navigate to **Settings → Data Inputs → Trellix ePO Input**

2. **Create New Input**
   - Click "New" to create a new input
   - Select **Input Name** (unique identifier)
   - Select **Data Source Type**:
     - `threat_events` - Threat detection events
     - `malware_detections` - Malware detection events
     - `host_status` - Host status information
     - `agent_status` - Agent status information
     - `policy_compliance` - Policy compliance data
     - `quarantine_events` - Quarantine events
     - `updates` - DAT update information
     - `user_actions` - User action audit logs

3. **Configure Input Settings**
   - **Polling Interval**: Override default if needed
   - **Batch Size**: Maximum events per collection
   - **Index**: Target index (default from setup)
   - **Sourcetype**: Auto-generated based on input type

4. **Advanced Settings** (Optional)
   - **Checkpoint Directory**: Custom checkpoint location
   - **Proxy Settings**: If ePO requires proxy access

5. **Save and Enable**

### Configuration Files

#### `inputs.conf` (Auto-generated)
Modular inputs are configured through Splunk Web or can be manually edited:

```ini
[trellix_epo://threat_events]
polling_interval = 300
batch_size = 1000
index = main
sourcetype = trellix_epo:threat_events
```

## 📊 Data Sources

### Threat Events
- **Sourcetype**: `trellix_epo:threat_events`
- **Frequency**: Recommended 5-15 minutes
- **Fields**: `detectionId`, `threatName`, `threatType`, `severity`, `host`, `src_ip`, `detectedUTC`
- **CIM**: Maps to `Intrusion_Detection`

### Malware Detections
- **Sourcetype**: `trellix_epo:malware_detections`
- **Frequency**: Recommended 5-15 minutes
- **Fields**: `malwareName`, `malwareType`, `fileHash`, `filePath`, `host`, `user`
- **CIM**: Maps to `Malware`

### Host Status
- **Sourcetype**: `trellix_epo:host_status`
- **Frequency**: Recommended 1-4 hours
- **Fields**: `host`, `os`, `src_ip`, `agentVersion`, `datVersion`, `lastUpdateTime`
- **CIM**: Maps to `Endpoint`

### Agent Status
- **Sourcetype**: `trellix_epo:agent_status`
- **Frequency**: Recommended 1-4 hours
- **Fields**: `host`, `agentVersion`, `agentStatus`, `lastCommunicationTime`
- **CIM**: Maps to `Endpoint`

### Policy Compliance
- **Sourcetype**: `trellix_epo:policy_compliance`
- **Frequency**: Recommended 1-6 hours
- **Fields**: `host`, `policyName`, `complianceStatus`, `violationCount`
- **CIM**: Maps to `Change`

### Quarantine Events
- **Sourcetype**: `trellix_epo:quarantine_events`
- **Frequency**: Recommended 5-15 minutes
- **Fields**: `host`, `filePath`, `fileHash`, `quarantineAction`
- **CIM**: Maps to `Malware`

### Updates
- **Sourcetype**: `trellix_epo:updates`
- **Frequency**: Recommended 1-6 hours
- **Fields**: `host`, `datVersion`, `engineVersion`, `updateStatus`
- **CIM**: Maps to `Endpoint`

### User Actions
- **Sourcetype**: `trellix_epo:user_actions`
- **Frequency**: Recommended 5-15 minutes
- **Fields**: `user`, `action`, `result`, `object`, `src_ip`, `timestampUTC`
- **CIM**: Maps to `Audit`

## 🔄 CIM Compliance

The add-on automatically normalizes events to Splunk Common Information Model:

| ePO Data | CIM Model | Key Fields |
|----------|-----------|------------|
| Malware Detections | Malware | `malware_name`, `file_hash`, `dest_host` |
| Threat Events | Intrusion_Detection | `signature`, `severity`, `dest_host`, `dest_ip` |
| Host Status | Endpoint | `dest_host`, `dest_ip`, `dest_os` |
| Policy Compliance | Change | `policy_name`, `compliance_status` |
| User Actions | Audit | `user`, `action`, `result`, `src_ip` |

### Verification

Verify CIM compliance using:
```splunk
index=* sourcetype="trellix_epo:*" | `datamodel(Intrusion_Detection,Intrusion_Detection)`
```

## 📈 Dashboard

### Accessing the Dashboards

1. Navigate to **Apps → Trellix ePO Add-on**
2. Choose from available dashboards:
   - **Trellix ePO Security Overview** - Comprehensive dashboard for REST API data
   - **Trellix ePO Syslog Threat Events** - Dashboard for syslog-based threat events

### Syslog Dashboard

The **Trellix ePO Syslog Threat Events** dashboard is specifically designed for threat events received via syslog from your Trellix ePO server. This dashboard:

- Works with standard syslog sourcetypes
- Automatically extracts threat information from syslog messages
- Supports flexible field extraction for various syslog formats
- Provides threat intelligence, IOC tracking, and host analysis
- Includes filters for sourcetype, host, severity, and custom search terms

**Key Features:**
- Threat event timeline and trends
- Severity distribution analysis
- Top affected hosts
- IOC extraction (hashes, IPs, file paths)
- Threat names and IDs extracted from syslog messages
- Heatmap visualization by day/hour
- Raw syslog message inspection

**Configuration:**
- Set the **Sourcetype Filter** to match your syslog sourcetypes (default: `syslog OR trellix_epo_syslog:threat_events`)
- Use **Additional Filter** to refine searches (e.g., `epo OR trellix OR threat`)
- Field extractions work automatically for common syslog formats

### REST API Dashboard

The **Trellix ePO Security Overview** dashboard provides comprehensive analysis of data collected via REST API:

### Dashboard Sections

#### 🛡 Security Overview
- Total threats (24h/7d)
- Infected hosts count
- Active malware detections
- Top malware families
- Severity distribution
- Threat trends over time

#### 💻 Endpoint Health
- Online vs Offline agents
- Unique endpoints count
- Agent status distribution
- DAT version distribution
- OS distribution
- Agent versions

#### 🚨 Threat Intelligence
- Top IOC hashes
- Top attack vectors
- Threat timeline
- Most affected hosts
- Threat heatmap by hour

#### 🔐 Policy & Compliance
- Policy violations count
- Non-compliant hosts
- Compliant hosts
- Policy compliance status
- Policy violations over time
- Top policy violations

#### 👤 User Activity
- Total user actions
- Failed logins
- Admin actions
- Top users by activity
- User actions over time
- Recent user actions

#### 📈 Advanced Analytics
- Threat heatmap by hour
- Threat severity vs type matrix
- Quarantine events timeline

### Dashboard Filters

Global filters available:
- **Time Range**: Customizable time window
- **Host**: Filter by specific hosts
- **Threat Type**: Filter by threat categories
- **Severity**: Filter by severity levels
- **DAT Version**: Filter by DAT versions

## 🔐 API Permissions

### Required ePO Permissions

The ePO user account needs the following permissions:

1. **Core Permissions**
   - `core.authenticate` - Authentication
   - `core.systemInfo` - System information

2. **Threat Permissions**
   - `epo.threat.detection` - Threat events
   - `epo.threat.malware` - Malware detections

3. **System Permissions**
   - `system.find` - System/host lookup
   - `epo.clienttask.find` - Agent status

4. **Compliance Permissions**
   - `epo.compliance.query` - Policy compliance

5. **Quarantine Permissions**
   - `epo.quarantine.query` - Quarantine events

6. **Update Permissions**
   - `epo.dat.query` - DAT updates

7. **Audit Permissions**
   - `epo.audit.query` - User actions

### ePO User Role

Recommended: Create a dedicated **Read-Only** service account with:
- Read permissions for all required objects
- API access enabled
- No modification permissions (least privilege)

## 🔧 Troubleshooting

### Common Issues

#### 1. Authentication Failures

**Symptoms**: `TrellixEPOAuthError: Authentication failed`

**Solutions**:
- Verify ePO URL and port are correct
- Check username and password
- Ensure ePO user has API access enabled
- Verify SSL certificate (disable verification if using self-signed certs)
- Check firewall rules between Splunk and ePO

**Debug**:
```bash
# Test authentication manually
python3 bin/trellix_epo_auth.py <epo_url> <username> <password> [port]
```

#### 2. No Events Appearing

**Symptoms**: Input runs but no events in Splunk

**Solutions**:
- Verify index exists: `| rest /services/data/indexes`
- Check input is enabled: Settings → Data Inputs
- Review Splunk logs: `$SPLUNK_HOME/var/log/splunk/splunkd.log`
- Check ePO API responses: Enable debug logging
- Verify time range: Events may be outside time window

**Debug**:
```bash
# Check modular input logs
tail -f $SPLUNK_HOME/var/log/splunk/splunkd.log | grep trellix_epo

# Test API client manually
python3 bin/trellix_epo_client.py <epo_url> <username> <password> [port]
```

#### 3. Rate Limiting Errors

**Symptoms**: `429 Too Many Requests` errors

**Solutions**:
- Increase polling interval
- Reduce batch size
- Configure multiple inputs with staggered schedules
- Contact ePO administrator to adjust rate limits

#### 4. SSL Certificate Errors

**Symptoms**: `SSL: CERTIFICATE_VERIFY_FAILED`

**Solutions**:
- Install ePO CA certificate in Splunk
- Set `ssl_verify = false` in setup (test environments only)
- Use proper certificate chain

#### 5. Missing Fields

**Symptoms**: Expected fields not extracted

**Solutions**:
- Verify `props.conf` and `transforms.conf` are loaded
- Check field extractions: `| extract reload=true`
- Review event format matches expected structure
- Rebuild field extractions: Settings → Fields → Field extractions

### Log Files

**Splunk Logs**:
- `$SPLUNK_HOME/var/log/splunk/splunkd.log` - Main Splunk log
- `$SPLUNK_HOME/var/log/splunk/python.log` - Python module logs

**Checkpoint Files**:
- `~/.splunk/checkpoints/TA-trellix-epo/*.checkpoint`

**Enable Debug Logging**:
```ini
# In $SPLUNK_HOME/etc/apps/TA-trellix-epo/default/logging.conf
[python]
level = DEBUG
```

## ⚡ Performance Tuning

### Optimization Tips

1. **Polling Intervals**
   - High-frequency data (threats, malware): 5-15 minutes
   - Medium-frequency (compliance): 1-6 hours
   - Low-frequency (host status): 1-4 hours

2. **Batch Sizes**
   - Start with 1000 events per batch
   - Increase if ePO supports larger queries
   - Monitor ePO server performance

3. **Indexing**
   - Use dedicated security index
   - Configure index retention policies
   - Consider index replication for HA

4. **Search Optimization**
   - Use indexed fields
   - Create summary indexes for common queries
   - Use data model acceleration for CIM

5. **Resource Limits**
   - Monitor Splunk CPU and memory usage
   - Adjust concurrent input limits
   - Use distributed deployment for scale

### Recommended Configuration

```ini
# High-volume inputs
[trellix_epo://threat_events]
polling_interval = 300
batch_size = 2000
index = security

# Low-volume inputs
[trellix_epo://host_status]
polling_interval = 3600
batch_size = 500
index = security
```

## 🔒 Security

### Best Practices

1. **Credential Storage**
   - Credentials stored in Splunk encrypted storage
   - Never hardcode credentials in configuration
   - Rotate credentials regularly

2. **Network Security**
   - Use SSL/TLS for all connections
   - Verify SSL certificates in production
   - Restrict network access (firewall rules)
   - Use VPN if needed

3. **Access Control**
   - Use dedicated service account with minimal permissions
   - Implement least privilege principle
   - Monitor user actions through audit logs

4. **Data Privacy**
   - Review indexed data for sensitive information
   - Configure index access controls
   - Implement data retention policies

5. **Compliance**
   - Ensure compliance with organizational policies
   - Follow data protection regulations (GDPR, etc.)
   - Document access and usage

## 📞 Support

### Resources

- **Splunkbase App Page**: [https://splunkbase.splunk.com/app/8351](https://splunkbase.splunk.com/app/8351)
- **GitHub Repository**: [https://github.com/sarat1kyan/TA-trellix-epo](https://github.com/sarat1kyan/TA-trellix-epo)
- **Splunk Documentation**: [https://docs.splunk.com](https://docs.splunk.com)
- **Splunk Answers**: [https://community.splunk.com](https://community.splunk.com)
- **Trellix ePO Documentation**: Check Trellix/McAfee product documentation

### Getting Help

1. Check [Troubleshooting](#troubleshooting) section
2. Review Splunk logs (`$SPLUNK_HOME/var/log/splunk/splunkd.log`)
3. Enable debug logging in `ta_trellix_epo_settings.conf`
4. Search [Splunk Answers](https://community.splunk.com) for similar issues
5. [Open a GitHub Issue](https://github.com/sarat1kyan/TA-trellix-epo/issues/new) with:
   - Splunk version
   - Add-on version
   - Error messages and log excerpts
   - Sanitized configuration

### Author & Maintainer

This add-on is developed and maintained by **Mher Saratikyan**.

- **Splunkbase Profile**: [Mher Saratikyan](https://splunkbase.splunk.com/apps/#/author/mher-saratikyan)
- **GitHub**: [@sarat1kyan](https://github.com/sarat1kyan)

## 📄 License

This Technology Add-on is provided as-is. Please review your organization's policies regarding third-party add-ons.

## 🔄 Version History

### Version 1.1.4 (2026-01-14)
- **Splunk Cloud Compatible** - Added python.version for modular inputs
- **Fixed modular input registration** - Script name matches scheme
- **Improved setup experience** - Better documentation and quick start
- See [CHANGELOG.md](CHANGELOG.md) for full details

### Version 1.1.3 (2026-01-14)
- **Bug Fix** - Fixed "No session key available" error in configure_credentials.py
- **Improved credential script** - Now prompts for Splunk admin credentials
- See [CHANGELOG.md](CHANGELOG.md) for full details

### Version 1.1.2 (2026-01-13)
- **New Setup Page** - Beautiful dashboard-based configuration guide
- **Fixed 404 errors** - Replaced legacy setup.xml with proper dashboard view
- **Improved navigation** - Direct links to setup and configuration
- See [CHANGELOG.md](CHANGELOG.md) for full details

### Version 1.1.1 (2026-01-11)
- **Bug Fix** - Fixed 404 error on Setup page
- **Fixed setup.xml** - Corrected REST endpoint paths and input types
- **Fixed REST handler** - Added all configuration fields support
- See [CHANGELOG.md](CHANGELOG.md) for full details

### Version 1.1.0 (2026-01-10)
- **Full CIM Compliance** - Added eventtypes.conf and tags.conf for complete data model integration
- **Enhanced Dashboard** - Security Command Center with interactive drilldowns and custom styling
- **Improved API Client** - Better error handling, retry logic, and response parsing
- **Utility Module** - New utils package with helper functions
- **Configuration Specs** - Complete .spec files for settings and inputs
- **Custom CSS** - Dark theme with GitHub-inspired styling
- See [CHANGELOG.md](CHANGELOG.md) for full details

### Version 1.0.0 Beta
- Initial release
- Support for all major ePO data sources
- CIM normalization via props.conf and transforms.conf
- Basic security dashboard
- Enterprise-ready implementation

---

*This project is maintained by an individual developer in their spare time. This project is not affiliated with Splunk or Trellix/CISCO*
---

## 🙏 Acknowledgments

**⭐ Star this repo if you found it helpful!**
[![BuyMeACoffee](https://raw.githubusercontent.com/pachadotdev/buymeacoffee-badges/main/bmc-donate-yellow.svg)](https://www.buymeacoffee.com/saratikyan)
[![Report Bug](https://img.shields.io/badge/Report-Bug-red.svg)](https://github.com/sarat1kyan/TA-trellix-epo/issues)
