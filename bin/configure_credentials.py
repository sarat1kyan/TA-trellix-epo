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

# Try to import Splunk libraries
try:
    import splunk.entity as entity
    import splunk.rest as rest
    SPLUNK_AVAILABLE = True
except ImportError:
    SPLUNK_AVAILABLE = False


def get_session_key():
    """Get session key from stdin (when run via splunk cmd)"""
    try:
        # When run via 'splunk cmd python', session key may be passed
        session_key = sys.stdin.readline().strip()
        if session_key:
            return session_key
    except:
        pass
    return None


def store_password_rest(session_key, username, password, realm="TA-trellix-epo"):
    """Store password using Splunk REST API"""
    try:
        # Check if credential already exists
        endpoint = f"/servicesNS/nobody/TA-trellix-epo/storage/passwords/{realm}%3A{username}%3A"
        
        try:
            # Try to update existing
            response, content = rest.simpleRequest(
                endpoint,
                sessionKey=session_key,
                postargs={"password": password},
                method="POST"
            )
            print(f"Updated existing credential for {username}")
            return True
        except:
            pass
        
        # Create new credential
        endpoint = "/servicesNS/nobody/TA-trellix-epo/storage/passwords"
        response, content = rest.simpleRequest(
            endpoint,
            sessionKey=session_key,
            postargs={
                "name": username,
                "password": password,
                "realm": realm
            },
            method="POST"
        )
        print(f"Created new credential for {username}")
        return True
        
    except Exception as e:
        print(f"Error storing credential: {e}")
        return False


def main():
    print("=" * 60)
    print("Trellix ePO Credential Configuration")
    print("=" * 60)
    print()
    
    if not SPLUNK_AVAILABLE:
        print("ERROR: This script must be run from Splunk.")
        print()
        print("Run it using:")
        print("  $SPLUNK_HOME/bin/splunk cmd python \\")
        print("    $SPLUNK_HOME/etc/apps/TA-trellix-epo/bin/configure_credentials.py")
        print()
        print("Or use the alternative method below.")
        print()
        print("-" * 60)
        print("ALTERNATIVE: Manual Credential Storage")
        print("-" * 60)
        print()
        print("Run this command on your Splunk server:")
        print()
        print('  curl -k -u admin:YOUR_SPLUNK_PASSWORD \\')
        print('    https://localhost:8089/servicesNS/nobody/TA-trellix-epo/storage/passwords \\')
        print('    -d name=splunkapi \\')
        print('    -d password="YOUR_EPO_PASSWORD" \\')
        print('    -d realm=TA-trellix-epo')
        print()
        return 1
    
    # Get session key
    session_key = get_session_key()
    if not session_key:
        print("No session key available. Please run via 'splunk cmd python'")
        return 1
    
    # Get credentials from user
    print("Enter your Trellix ePO credentials:")
    print()
    
    username = input("ePO Username [splunkapi]: ").strip() or "splunkapi"
    password = getpass.getpass("ePO Password: ")
    
    if not password:
        print("ERROR: Password cannot be empty")
        return 1
    
    # Store the credential
    print()
    print("Storing credential securely...")
    
    if store_password_rest(session_key, username, password):
        print()
        print("SUCCESS! Credential stored securely.")
        print()
        print("Next steps:")
        print("1. Configure ePO server via Apps → Trellix ePO Add-on → Set up")
        print("   Or copy default/ta_trellix_epo_settings.conf to local/ and edit")
        print("2. Enable inputs via Settings → Data Inputs → Trellix ePO Input")
        print("   Or copy input stanzas from default/inputs.conf to local/inputs.conf")
        print("3. Restart Splunk")
        return 0
    else:
        print("FAILED to store credential.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

