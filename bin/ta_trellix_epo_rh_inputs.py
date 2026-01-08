"""
REST Handler for Trellix ePO Inputs
Handles CRUD operations for modular input configurations
"""

import os
import sys

# Add lib folder to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import splunk.admin as admin
import splunk.clilib.cli_common as cli_common


class TrellixEpoInputsHandler(admin.MConfigHandler):
    """
    REST handler for managing Trellix ePO modular input configurations.
    """

    def setup(self):
        """
        Set up supported arguments for the REST endpoint.
        """
        if self.requestedAction == admin.ACTION_EDIT:
            # Define optional arguments for input configuration
            for arg in [
                "name",
                "interval",
                "index",
                "sourcetype",
                "disabled",
                "epo_server",
                "api_endpoint",
                "start_time",
                "batch_size",
            ]:
                self.supportedArgs.addOptArg(arg)
        
        if self.requestedAction == admin.ACTION_CREATE:
            # Required arguments for creating new input
            self.supportedArgs.addReqArg("name")
            
            # Optional arguments
            for arg in [
                "interval",
                "index",
                "sourcetype",
                "disabled",
                "epo_server",
                "api_endpoint",
                "start_time",
                "batch_size",
            ]:
                self.supportedArgs.addOptArg(arg)

    def handleList(self, confInfo):
        """
        Handle list request - returns all configured inputs.
        """
        conf_file = "inputs"
        
        try:
            # Get all stanzas from inputs.conf for this add-on
            conf_dict = cli_common.getConfStanzas(conf_file)
            
            for stanza, settings in conf_dict.items():
                # Filter for trellix_epo inputs
                if stanza.startswith("trellix_epo://"):
                    for key, val in settings.items():
                        confInfo[stanza].append(key, val)
        except Exception:
            # Return empty if no inputs configured
            pass

    def handleEdit(self, confInfo):
        """
        Handle edit request - updates input configuration.
        """
        conf_file = "inputs"
        
        # Get the stanza name from the request
        stanza_name = self.callerArgs.id
        
        # Build args dict from caller args
        args = {}
        for arg in self.callerArgs.data:
            if self.callerArgs.data[arg][0] is not None:
                args[arg] = self.callerArgs.data[arg][0]
        
        # Write to conf file
        self.writeConf(conf_file, stanza_name, args)

    def handleCreate(self, confInfo):
        """
        Handle create request - creates new input.
        """
        conf_file = "inputs"
        
        # Get the input name
        input_name = self.callerArgs.id
        if not input_name.startswith("trellix_epo://"):
            input_name = f"trellix_epo://{input_name}"
        
        # Build args dict from caller args
        args = {}
        for arg in self.callerArgs.data:
            if self.callerArgs.data[arg][0] is not None:
                args[arg] = self.callerArgs.data[arg][0]
        
        # Set defaults if not provided
        if "disabled" not in args:
            args["disabled"] = "0"
        if "interval" not in args:
            args["interval"] = "300"
        
        # Write to conf file
        self.writeConf(conf_file, input_name, args)

    def handleRemove(self, confInfo):
        """
        Handle remove request - disables/removes input.
        """
        conf_file = "inputs"
        stanza_name = self.callerArgs.id
        
        # Mark as disabled rather than deleting
        self.writeConf(conf_file, stanza_name, {"disabled": "1"})


# Initialize the handler
if __name__ == "__main__":
    admin.init(TrellixEpoInputsHandler, admin.CONTEXT_APP_AND_USER)

