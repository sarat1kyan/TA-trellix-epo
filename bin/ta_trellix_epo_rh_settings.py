"""
REST Handler for Trellix ePO Settings
Handles CRUD operations for add-on configuration settings
"""

import os
import sys

# Add lib folder to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import splunk.admin as admin
import splunk.clilib.cli_common as cli_common


class TrellixEpoSettingsHandler(admin.MConfigHandler):
    """
    REST handler for managing Trellix ePO add-on settings.
    """

    def setup(self):
        """
        Set up supported arguments for the REST endpoint.
        """
        if self.requestedAction == admin.ACTION_EDIT:
            # Define optional arguments for settings
            for arg in [
                "epo_server",
                "epo_port",
                "username",
                "password",
                "verify_ssl",
                "timeout",
                "log_level",
            ]:
                self.supportedArgs.addOptArg(arg)

    def handleList(self, confInfo):
        """
        Handle list request - returns current settings.
        """
        conf_file = "ta_trellix_epo_settings"
        
        try:
            conf = cli_common.getConfStanza(conf_file, "general")
            for key, val in conf.items():
                confInfo["general"].append(key, val)
        except Exception:
            # Return empty if conf doesn't exist yet
            pass

    def handleEdit(self, confInfo):
        """
        Handle edit request - updates settings.
        """
        conf_file = "ta_trellix_epo_settings"
        
        # Get the stanza name from the request
        stanza_name = self.callerArgs.id if self.callerArgs.id else "general"
        
        # Build args dict from caller args
        args = {}
        for arg in self.callerArgs.data:
            if self.callerArgs.data[arg][0] is not None:
                args[arg] = self.callerArgs.data[arg][0]
        
        # Write to conf file
        self.writeConf(conf_file, stanza_name, args)

    def handleCreate(self, confInfo):
        """
        Handle create request - creates new settings stanza.
        """
        self.handleEdit(confInfo)

    def handleRemove(self, confInfo):
        """
        Handle remove request - removes settings stanza.
        """
        # Implementation for removing stanzas if needed
        pass


# Initialize the handler
if __name__ == "__main__":
    admin.init(TrellixEpoSettingsHandler, admin.CONTEXT_APP_AND_USER)

