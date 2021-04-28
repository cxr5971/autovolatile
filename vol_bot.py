
import subprocess

class Vol_Bot:


    def __init__(self, memory_file, vol_loc):
        self.memory_file = memory_file
        self.vol_loc = vol_loc


    def set_memory_file(self, memory_file):
        self.memory_file = memory_file


    def set_vol_loc(self, filepath):
        self.vol_loc = filepath

    def pslist(self):
        pslist_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.pslist.PsList"], capture_output=True, text=True)
        print(pslist_output.stdout)

    def handles(self):
        handles_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.handles.Handles"], capture_output=True, text=True)
        print(handles_output.stdout)

    def netscan(self):
        netscan_output = subprocess.run([self.vol_loc, "-f", self.memory_file, "windows.netscan.NetScan"], capture_output=True, text=True)
        print(netscan_output.stdout)
