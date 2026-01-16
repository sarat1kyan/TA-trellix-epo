#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Trellix ePO Credential Configuration Script
Run this script to securely store your ePO password in Splunk's encrypted storage.

Usage (run from Splunk server):
    $SPLUNK_HOME/bin/splunk cmd python $SPLUNK_HOME/etc/apps/TA-trellix-epo/bin/configure_credentials.py
"""

import sys
import os
import getpass
import ssl

# Try to import Splunk libraries
try:
    import splunklib.client as client
    SPLUNKLIB_AVAILABLE = True
except ImportError:
    SPLUNKLIB_AVAILABLE = False

# Also try the REST module for alternative method
try:
    import splunk.rest as rest
    SPLUNK_REST_AVAILABLE = True
except ImportError:
    SPLUNK_REST_AVAILABLE = False


def get_splunk_connection(host, port, username, password):
    """Connect to Splunk and return a service object"""
    try:
        # Create SSL context that doesn't verify (for self-signed certs)
        service = client.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            autologin=True
        )
        return service
    except Exception as e:
        print(f"Error connecting to Splunk: {e}")
        return None


def store_password_splunklib(service, epo_username, epo_password, realm="TA-trellix-epo"):
    """Store password using splunklib"""
    try:
        # Get the storage/passwords collection
        storage_passwords = service.storage_passwords
        
        # Check if credential already exists
        existing = None
        for pwd in storage_passwords:
            if pwd.realm == realm and pwd.username == epo_username:
                existing = pwd
                break
        
        if existing:
            # Delete existing and recreate (splunklib doesn't have update)
            existing.delete()
            print(f"Removed existing credential for {epo_username}")
        
        # Create new credential
        storage_passwords.create(epo_password, epo_username, realm)
        print(f"Created credential for {epo_username}")
        return True
        
    except Exception as e:
        print(f"Error storing credential: {e}")
        return False


def main():
    print("=" * 60)
    print("Trellix ePO Credential Configuration")
    print("=" * 60)
    print()
    
    if not SPLUNKLIB_AVAILABLE:
        print("ERROR: splunklib not available.")
        print()
        print("Please install it with:")
        print("  pip install splunk-sdk")
        print()
        print("Or use the alternative curl method below.")
        print()
        print("-" * 60)
        print("ALTERNATIVE: Manual Credential Storage via curl")
        print("-" * 60)
        print()
        print("Run this command on your Splunk server:")
        print()
        print('  curl -k -u admin:YOUR_SPLUNK_PASSWORD \\')
        print('    https://localhost:8089/servicesNS/nobody/TA-trellix-epo/storage/passwords \\')
        print('    -d name=YOUR_EPO_USERNAME \\')
        print('    -d password="YOUR_EPO_PASSWORD" \\')
        print('    -d realm=TA-trellix-epo')
        print()
        return 1
    
    # Get Splunk connection details
    print("First, authenticate with Splunk to store credentials securely.")
    print()
    
    splunk_host = input("Splunk Host [localhost]: ").strip() or "localhost"
    splunk_port = input("Splunk Management Port [8089]: ").strip() or "8089"
    splunk_user = input("Splunk Admin Username [admin]: ").strip() or "admin"
    splunk_pass = getpass.getpass("Splunk Admin Password: ")
    
    if not splunk_pass:
        print("ERROR: Splunk password cannot be empty")
        return 1
    
    print()
    print("Connecting to Splunk...")
    
    # Connect to Splunk
    try:
        splunk_port = int(splunk_port)
    except ValueError:
        print("ERROR: Invalid port number")
        return 1
    
    service = get_splunk_connection(splunk_host, splunk_port, splunk_user, splunk_pass)
    
    if not service:
        print("ERROR: Failed to connect to Splunk")
        print()
        print("Please check:")
        print("  1. Splunk is running")
        print("  2. Management port (default 8089) is accessible")
        print("  3. Username and password are correct")
        return 1
    
    print("Connected to Splunk successfully!")
    print()
    
    # Get ePO credentials from user
    print("-" * 60)
    print("Now enter your Trellix ePO credentials:")
    print("-" * 60)
    print()
    
    epo_username = input("ePO Username: ").strip()
    if not epo_username:
        print("ERROR: ePO username cannot be empty")
        return 1
    
    epo_password = getpass.getpass("ePO Password: ")
    if not epo_password:
        print("ERROR: ePO password cannot be empty")
        return 1
    
    epo_password_confirm = getpass.getpass("Confirm ePO Password: ")
    if epo_password != epo_password_confirm:
        print("ERROR: Passwords do not match")
        return 1
    
    # Store the credential
    print()
    print("Storing credential securely...")
    
    if store_password_splunklib(service, epo_username, epo_password):
        print()
        print("=" * 60)
        print("SUCCESS! Credential stored securely.")
        print("=" * 60)
        print()
        print("Next steps:")
        print()
        print("1. Create local settings configuration:")
        print("   cp $SPLUNK_HOME/etc/apps/TA-trellix-epo/default/ta_trellix_epo_settings.conf \\")
        print("      $SPLUNK_HOME/etc/apps/TA-trellix-epo/local/ta_trellix_epo_settings.conf")
        print()
        print("2. Edit local/ta_trellix_epo_settings.conf with your ePO server details:")
        print(f"   [general]")
        print(f"   epo_server = your-epo-server.company.com")
        print(f"   epo_port = 8443")
        print(f"   username = {epo_username}")
        print()
        print("3. Enable inputs in local/inputs.conf (set disabled = 0)")
        print()
        print("4. Restart Splunk:")
        print("   $SPLUNK_HOME/bin/splunk restart")
        print()
        return 0
    else:
        print("FAILED to store credential.")
        return 1


if __name__ == "__main__":
    # Disable SSL warnings for self-signed certificates
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except (ImportError, AttributeError):
        pass
    
    sys.exit(main())
