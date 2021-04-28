
class Vol_Parser:


    def __init__(self, plugin_type):
        self.plugin_type = plugin_type
        if self.plugin_type == "windows.pslist.PsList":
            self.header_cols = 11
        elif self.plugin_type == "windows.psscan.PsScan":
            return
        elif self.plugin_type == "windows.pstree.PsTree":
            return
        elif self.plugin_type == "windows.netscan.NetScan":
            return
        elif self.plugin_type == "windows.handles.Handles":
            return
        elif self.plugin_type == "windows.modules.Modules":
            return
        elif self.plugin_type == "windows.dlllist.DllList":
            return
        elif self.plugin_type == "windows.cmdline.CmdLine":
            return
        elif self.plugin_type == "windows.svcscan.SvcScan":
            return

#Need to come back and add yarascan
#Return list of process_api objects
    def process_data(self,output):
        data = tab_parser(output)
        for entry in data[1:]
            #LEFT OFF HERE


    def tab_parser(self, output):
        output_list = []

        for line in output:
            
            if current_line == "":
                continue

            current_line = line.split('\t'):
            if current_line[0] == "Volatility":
                continue

            line_list = []
            for item in current_line:
                line_list.append(item)

            output_list.append(item)
        return output_list



