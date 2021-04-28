
class Vol_Parser:


    def __init__(self, plugin_type):
        self.plugin_type = plugin_type




#Need to come back and add yarascan
#Return list of process_api objects
    def parse_data(self,output):
        data = tab_parser(output)

        #Returns a list of process dicts
        if self.plugin_type == "windows.pslist.PsList":
            process_data = parse_process(data)
            return process_data
        #Returns a list of process dicts
        elif self.plugin_type == "windows.psscan.PsScan":
            return parse_process(data)
        #PSTREE IS BROKE IN VOL3
        # Returns a 
        #elif self.plugin_type == "windows.pstree.PsTree":
        #    return
        elif self.plugin_type == "windows.netscan.NetScan":
            return parse_netscan(data)
        elif self.plugin_type == "windows.handles.Handles":
            return parse_handles(data)
        elif self.plugin_type == "windows.modules.Modules":
            return parse_modules(data)
        elif self.plugin_type == "windows.dlllist.DllList":
            return parse_dlllist(data)
        elif self.plugin_type == "windows.cmdline.CmdLine":
            return parse_cmdline(data)
        elif self.plugin_type == "windows.svcscan.SvcScan":
            return parse_svcscan(data)

            


    def tab_parser(self, output):
        output_list = []

        for line in output:
            
            if current_line == "":
                continue

            current_line = line.split('\t'):
            if current_line[0] == "Volatility":
                continue

            if current_line[0] == "Progress:":
                continue

            line_list = []
            for item in current_line:
                line_list.append(item)

            output_list.append(item)
        return output_list

    #Used for pslist and psscan
    #Returns a list that contains a dictionary which a sub dictionary containing info about processes
    def parse_process(self, data):
        all_process_list = []
        for entry in data[1:]:
            outer_process_dict = {}
            inner_process_dict = {}
            inner_process_dict['PID'] = entry[0]
            inner_process_dict['PPID'] = entry[1]
            inner_process_dict['ImageFileName'] = entry[2]
            inner_process_dict['Offset'] = entry[3]
            inner_process_dict['Threads'] = entry[4]
            inner_process_dict['Handles'] = entry[5]
            inner_process_dict['SessionID'] = entry[6]
            inner_process_dict['Wow64'] = entry[7]
            inner_process_dict['CreateTime'] = entry[8]
            inner_process_dict['ExitTime'] = entry[9]
            inner_process_dict['FileOutput'] = entry[10]
            outer_process_dict[entry[0]] = inner_process_dict
            all_process_list.append(outer_process_dict)

        return all_process_list

    #Used for modules plugins
    def parse_modules(self, data):
        all_modules_list = []
        for entry in data[1:]:
            outer_modules_dict = {}
            inner_modules_dict = {}
            inner_modules_dict['Offset'] = entry[0]
            inner_modules_dict['Base'] = entry[1]
            inner_modules_dict['Size'] = entry[2]
            inner_modules_dict['Name'] = entry[3]
            inner_modules_dict['Path'] = entry[4]
            inner_modules_dict['FileOutput'] = entry[5]
            outer_modules_dict[entry[0]] = inner_modules_dict
            all_modules_list.append(outer_modules_dict)

        return all_modules_list
    

    def parse_dlllist(self, data):
        all_dll_list = []
        for entry in data[1:]:
            outer_dll_dict = {}
            inner_dll_dict = {}
            inner_dll_dict['PID'] = entry[0]
            inner_dll_dict['Process Base'] = entry[1]
            inner_dll_dict['Size'] = entry[2]
            inner_dll_dict['Name'] = entry[3]
            inner_dll_dict['Path'] = entry[4]
            inner_dll_dict['LoadTime'] = entry[5]
            inner_dll_dict['File output'] = entry[6]
            outer_dll_dict[entry[3]] = inner_dll_dict
            all_dll_list.append(outer_dll_dict)

        return all_dll_list


    def parse_cmdline(self, data):
        all_cmdline_list = []
        for entry in data[1:]:
            outer_cmdline_dict = {}
            inner_cmdline_dict = {}
            inner_cmdline_dict['PID'] = entry[0]
            inner_cmdline_dict['Process'] = entry[1]
            inner_cmdline_dict['Args'] = entry[2]
            outer_cmdline_dict[entry[0]] = inner_cmdline_dict
            all_cmdline_list.append(outer_cmdline_dict)
        return all_cmdline_list


    def parse_svcscan(self, data):
        all_svcscan_list = []
        for entry in data[1:]:
            outer_svcscan_dict = {}
            inner_svcscan_dict = {}
            inner_svcscan_dict['Offset'] = entry[0]
            inner_svcscan_dict['Order'] = entry[1]
            inner_svcscan_dict['PID'] = entry[2]
            inner_svcscan_dict['Start'] = entry[3]
            inner_svcscan_dict['State'] = entry[4]
            inner_svcscan_dict['Type'] = entry[5]
            inner_svcscan_dict['Name'] = entry[6]
            inner_svcscan_dict['Display'] = entry[7]
            inner_svcscan_dict['Binary'] = entry[8]
            outer_svcscan_dict[entry[6]] = inner_svcscan_dict
            all_svcscan_list.append(outer_svcscan_dict)

        return all_svcscan_list

    def parse_handles(self, data):
        all_handles_list = []
        for entry in data[1:]:
            outer_handles_dict = {}
            inner_handles_dict = {}
            inner_handles_dict['PID'] = entry[0]
            inner_handles_dict['Process'] = entry[1]
            inner_handles_dict['Offset'] = entry[2]
            inner_handles_dict['HandleValue'] = entry[3]
            inner_handles_dict['Type'] = entry[4]
            inner_handles_dict['GrantedAccess'] = entry[5]
            inner_handles_dict['Name'] = entry[6]
            outer_handles_dict['OffsetID'] = inner_handles_dict
            all_handles_list.append(outer_handles_dict)

        return all_handles_list


    def parse_netscan(self, data):
        all_netscan_list = []
        for entry in data[1:]:
            outer_netscan_dict = {}
            inner_netscan_dict = {}
            inner_netscan_dict['Offset'] = entry[0]
            inner_netscan_dict['Proto'] = entry[1]
            inner_netscan_dict['LocalAddr'] = entry[2]
            inner_netscan_dict['LocalPort'] = entry[3]
            inner_netscan_dict['ForeignAddr'] = entry[4]
            inner_netscan_dict['ForeignPort'] = entry[5]
            inner_netscan_dict['State'] = entry[6]
            inner_netscan_dict['PID'] = entry[7]
            inner_netscan_dict['Owner'] = entry[8]
            inner_netscan_dict['Created'] = entry[9]
            outer_netscan_dict[entry[0]] = inner_netscan_dict
            all_netscan_list.append(outer_netscan_dict)

        return all_netscan_list







