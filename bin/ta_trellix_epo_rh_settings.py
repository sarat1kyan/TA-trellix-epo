"""
REST Handler for Trellix ePO Settings
Handles CRUD operations for add-on configuration settings
"""

import os
import sys

# Add lib folder to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import splunk.admin as admin


class TrellixEpoSettingsHandler(admin.MConfigHandler):
    """
    REST handler for managing Trellix ePO add-on settings.
    Supports both 'general' and 'proxy' stanzas.
    """

    # All supported fields for the settings configuration
    GENERAL_FIELDS = [
        "epo_server",
        "epo_port",
        "username",
        "password",
        "use_ssl",
        "verify_ssl",
        "polling_interval",
        "batch_size",
        "timeout",
        "retry_attempts",
        "log_level",
    ]
    
    PROXY_FIELDS = [
        "use_proxy",
        "proxy_server",
        "proxy_port",
        "proxy_username",
        "proxy_password",
    ]

    def setup(self):
        """
        Set up supported arguments for the REST endpoint.
        """
        if self.requestedAction == admin.ACTION_EDIT:
            # Add all general fields as optional arguments
            for arg in self.GENERAL_FIELDS:
                self.supportedArgs.addOptArg(arg)
            # Add all proxy fields as optional arguments
            for arg in self.PROXY_FIELDS:
                self.supportedArgs.addOptArg(arg)
        
        if self.requestedAction == admin.ACTION_CREATE:
            # All fields are optional for create
            for arg in self.GENERAL_FIELDS + self.PROXY_FIELDS:
                self.supportedArgs.addOptArg(arg)

    def _get_splunk_home(self):
        """Get SPLUNK_HOME with cross-platform fallback"""
        splunk_home = os.environ.get("SPLUNK_HOME")
        if splunk_home:
            return splunk_home
        # Cross-platform fallbacks
        if os.name == 'nt':  # Windows
            return r"C:\Program Files\Splunk"
        return "/opt/splunk"
    
    def _mark_app_configured(self):
        """
        Mark the app as configured by setting is_configured = 1 in app.conf
        This removes the setup page prompt from Splunk UI.
        """
        import logging
        splunk_home = self._get_splunk_home()
        local_dir = os.path.join(splunk_home, "etc", "apps", "TA-trellix-epo", "local")
        app_conf_path = os.path.join(local_dir, "app.conf")
        
        try:
            # Ensure local directory exists
            if not os.path.exists(local_dir):
                os.makedirs(local_dir)
            
            # Read existing local app.conf if it exists
            import configparser
            config = configparser.ConfigParser()
            if os.path.exists(app_conf_path):
                config.read(app_conf_path)
            
            # Set is_configured = 1
            if not config.has_section("install"):
                config.add_section("install")
            config.set("install", "is_configured", "1")
            
            # Write back
            with open(app_conf_path, "w") as f:
                config.write(f)
            
            logging.info("Marked TA-trellix-epo as configured")
            
        except Exception as e:
            logging.warning(f"Could not mark app as configured: {str(e)}")

    def handleList(self, confInfo):
        """
        Handle list request - returns current settings.
        """
        conf_file = "ta_trellix_epo_settings"
        splunk_home = self._get_splunk_home()
        
        try:
            # Read the conf file
            conf_path = os.path.join(
                splunk_home,
                "etc", "apps", "TA-trellix-epo", "local",
                f"{conf_file}.conf"
            )
            
            # Try local first, then default
            if not os.path.exists(conf_path):
                conf_path = os.path.join(
                    splunk_home,
                    "etc", "apps", "TA-trellix-epo", "default",
                    f"{conf_file}.conf"
                )
            
            if os.path.exists(conf_path):
                import configparser
                config = configparser.ConfigParser()
                config.read(conf_path)
                
                for section in config.sections():
                    for key, val in config.items(section):
                        # Mask password fields
                        if "password" in key.lower():
                            confInfo[section].append(key, "********")
                        else:
                            confInfo[section].append(key, val)
            else:
                # Return default empty stanzas
                confInfo["general"].append("epo_server", "")
                confInfo["general"].append("epo_port", "8443")
                confInfo["general"].append("use_ssl", "1")
                confInfo["general"].append("verify_ssl", "1")
                confInfo["general"].append("polling_interval", "300")
                confInfo["general"].append("batch_size", "1000")
                confInfo["general"].append("timeout", "30")
                confInfo["general"].append("retry_attempts", "3")
                confInfo["general"].append("log_level", "INFO")
                
        except Exception as e:
            # Log error but return empty to avoid breaking UI
            import logging
            logging.error(f"Error reading settings: {str(e)}")

    def handleEdit(self, confInfo):
        """
        Handle edit request - updates settings.
        Also marks the app as configured when epo_server and username are set.
        """
        conf_file = "ta_trellix_epo_settings"
        
        # Get the stanza name from the request
        stanza_name = self.callerArgs.id if self.callerArgs.id else "general"
        
        # Build args dict from caller args
        args = {}
        for arg in self.callerArgs.data:
            val = self.callerArgs.data[arg]
            if val and len(val) > 0 and val[0] is not None:
                args[arg] = val[0]
        
        # Write to conf file
        if args:
            self.writeConf(conf_file, stanza_name, args)
            
            # If we're updating general stanza with epo_server, mark app as configured
            if stanza_name == "general" and "epo_server" in args:
                self._mark_app_configured()

    def handleCreate(self, confInfo):
        """
        Handle create request - creates new settings stanza.
        """
        self.handleEdit(confInfo)

    def handleRemove(self, confInfo):
        """
        Handle remove request - removes settings stanza.
        Not typically used for settings, but required by interface.
        """
        pass


# Initialize the handler
if __name__ == "__main__":
    admin.init(TrellixEpoSettingsHandler, admin.CONTEXT_APP_AND_USER)
