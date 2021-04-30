from vol_parser import Vol_Parser
import subprocess

class Vol_Bot:


    def __init__(self, memory_file, vol_loc):
        self.memory_file = memory_file
        self.vol_loc = vol_loc
        self.vol_parser = Vol_Parser()
        self.output_dict = None


    def set_memory_file(self, memory_file):
        self.memory_file = memory_file

    def set_output_dict(self, output_dict):
        self.output_dict = output_dict

    def set_vol_loc(self, filepath):
        self.vol_loc = filepath

    #Function: pslist
    #Parameters: self (this object)
    #Description: processes the volatility pslist plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def pslist(self):
        pslist_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.pslist.PsList"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.pslist.PsList")
        return(self.vol_parser.parse_data(pslist_output.stdout))

    #Function: psscan
    #Parameters: self (this object)
    #Description: processes the volatility psscan plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def psscan(self):
        psscan_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.psscan.PsScan"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.psscan.PsScan")
        return(self.vol_parser.parse_data(psscan_output.stdout))


    #Function: modules
    #Parameters: self (this object)
    #Description: processes the volatility modules plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def modules(self):
        modules_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.modules.Modules"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.modules.Modules")
        return(self.vol_parser.parse_data(modules_output.stdout))

    #Function: dlllist
    #Parameters: self (this object)
    #Description: processes the volatility dlllist plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def dlllist(self):
        dlllist_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.dlllist.DllList"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.dlllist.DllList")
        return(self.vol_parser.parse_data(dlllist_output.stdout))


    #Function: cmdline
    #Parameters: self (this object)
    #Description: processes the volatility cmdline plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def cmdline(self):
        cmdline_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.cmdline.CmdLine"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.cmdline.CmdLine")
        return(self.vol_parser.parse_data(cmdline_output.stdout))

    #Function: svcscan
    #Parameters: self (this object)
    #Description: processes the volatility svcscan plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def svcscan(self):
        svcscan_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.svcscan.SvcScan"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.svcscan.SvcScan")
        return(self.vol_parser.parse_data(svcscan_output.stdout))

    #Function: handles
    #Parameters: self (this object)
    #Description: processes the volatility handles plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def handles(self):
        handles_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.handles.Handles"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.handles.Handles")
        return(self.vol_parser.parse_data(handles_output.stdout))


    #Function: netscan
    #Parameters: self (this object)
    #Description: processes the volatility netscan plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def netscan(self):
        netscan_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.netscan.NetScan"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.netscan.NetScan")
        return(self.vol_parser.parse_data(netscan_output.stdout))
    
    #UNUSED
    #Function: yarascan
    #Parameters: self (this object)
    #Description: processes the volatility yarascan plugin using hte memory file and vol.py location give upon creation of this object (from cmd args)
    #Returns: Returns the full parsed data (list of dicts)
    def yarascan(self, yarafile):
        yarafile_string = "--yara-file="+yarafile
        yarascan_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "yarascan.YaraScan", yarafile_string], capture_output=True, text=True)
        self.vol_parser.set_plugin("yarascan.YaraScan")
        return(self.vol_parser.parse_data(yarascan_output))
