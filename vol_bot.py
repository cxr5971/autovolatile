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

    def pslist(self):
        pslist_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.pslist.PsList"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.pslist.PsList")
        return(self.vol_parser.parse_data(pslist_output.stdout))

    def psscan(self):
        psscan_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.pslist.PsList"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.psscan.PsScan")
        return(self.vol_parser.parse_data(psscan_output.stdout))

    def modules(self):
        modules_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.psscan.PsScan"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.modules.Modules")
        return(self.vol_parser.parse_data(modules_output.stdout))

    def dlllist(self):
        dlllist_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.dlllist.DllList"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.dlllist.DllList")
        return(self.vol_parser.parse_data(dlllist_output.stdout))

    def cmdline(self):
        cmdline_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.cmdline.CmdLine"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.cmdline.CmdLine")
        return(self.vol_parser.parse_data(cmdline_output.stdout))

    def svcscan(self):
        svcscan_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.svcscan.SvcScan"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.svcscan.SvcScan")
        return(self.vol_parser.parse_data(svcscan_output.stdout))


    def handles(self):
        handles_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.handles.Handles"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.handles.Handles")
        return(self.vol_parser.parse_data(handles_output.stdout))

    def netscan(self):
        netscan_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.netscan.NetScan"], capture_output=True, text=True)
        self.vol_parser.set_plugin("windows.netscan.NetScan")
        return(self.vol_parser.parse_data(netscan_output.stdout))
