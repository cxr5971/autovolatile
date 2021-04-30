#Author: Cullen Rezendes
#Class Name: Vol_Parser
#Description: Vol_Parser is a module designed to parse any Volatility plugin output received from
# Vol_Bot objects. The output will be a dictionary containing all of the data needed for the report





class Vol_Parser:

    #Function: __init__
    #Parameters: self (this object)
    #Description: Set the plugin type to None for now
    #Returns: returns a Vol_Parser object
    def __init__(self):
        self.plugin_type = None

    #Function: set_plugin
    #Parameters: self (this object), plugin_type (plugin to parse, ex. windows.psscan.PsScan)
    #Description: sets the volatility plugin type
    #Returns: None
    def set_plugin(self, plugin_type):
        self.plugin_type = plugin_type

    #Function: tab_parser
    #Parameters: output (the vol plugin output)
    #Description: Takes output from a vol plugin and parses the first few lines out, getting it ready for storing the data
    #Returns: output_list (list of entries from the Vol plugin output, ex. each line being a process in the case of psscan)
    @staticmethod
    def tab_parser(output):
        output = output.split("\n")
        output_list = []
        
        for line in output:
            
            if line == "":
                continue

            current_line = line.split('\t')
            if current_line[0][0:10] == "Volatility":
                continue

            if current_line[0][0:9] == "Progress:":
                continue

            line_list = []
            for item in current_line:
                line_list.append(item)

            output_list.append(line_list)
        return output_list

    #Function: parse_process
    #Parameters: self (this object), data (the data retrieved after parsing from tab_parser. Just has the actual important vol data)
    #Description: Parses the pslist or psscan process data into a list of all processes
    #Returns: list of dicts that contain process info
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

    #Function: parse_modules
    #Parameters: self (this object), data (data retrived from volatility modules plugin after parsing tabs)
    #Description: Parses the modules data into a list of all modules
    #Returns: list of dicts that contain module information

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
    
    #Function: parse_dlllist
    #Parameters: self (this object), data (data retrieved from vol dlllist plugin after parsing tabs)
    #Description: Parses the dlllist data into a list of all DLLs
    #Returns: list of dicts that contain dll information
    def parse_dlllist(self, data):
        all_dll_list = []
        for entry in data[1:]:
            outer_dll_dict = {}
            inner_dll_dict = {}
            inner_dll_dict['PID'] = entry[0]
            inner_dll_dict['Process'] = entry[1]
            inner_dll_dict['Base'] = entry[2]
            inner_dll_dict['Size'] = entry[3]
            inner_dll_dict['Name'] = entry[4]
            inner_dll_dict['Path'] = entry[5]
            inner_dll_dict['LoadTime'] = entry[6]
            inner_dll_dict['File output'] = entry[7]
            outer_dll_dict[entry[3]] = inner_dll_dict
            all_dll_list.append(outer_dll_dict)

        return all_dll_list

    #Function: parse_cmdline
    #Parameters: self (this object), data (data retrieved from vol cmdline plugin after parsing tabs)
    #Description: Parses the cmdline data into a list of all cmdline activities
    #Returns: list of dicts that contain cmdline information
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


    #Function: parse_svcscan
    #Parameters: self (this object), data (data retrieved from vol svcscan plugin after parsing tabs)
    #Description: Parses the svcscan data into a list of all services
    #Returns: list of dicts that contain services information
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

    #Function: parse_handles
    #Parameters: self (this object), data (data retrieved from vol handles plugin after parsing tabs)
    #Description: Parses the handles data into a list of all handles
    #Returns: list of dicts that contain handle information
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

    #Function: parse_netscan
    #Parameters: self (this object), data (data retrieved from vol netscan plugin after parsing tabs)
    #Description: Parses the netscan data into a list of all network connections
    #Returns: list of dicts that contain network connection information
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


    #UNUSUED AS OF RIGHT NOW
    #Function: parse_yarascan
    #Parameters: self (this object), data (data retrieved from vol yarascan plugin after parsing tabs)
    #Description: Parses the yarascan data into a list of all items found from yara
    #Returns: list of dicts that contain yarascan information
    def parse_yarascan(self, data):
        all_yarascan_list = []
        for entry in data[1:]:
            outer_yarascan_dict = {}
            inner_yarascan_dict = {}
            inner_yarascan_dict['Offset'] = entry[0]
            inner_yarascan_dict['IP'] = entry[1]
            inner_yarascan_dict['Component'] = entry[2]
            inner_yarascan_dict['Value'] = entry[3]
            inner_yarascan_dict['ForeignAddr'] = entry[4]
            inner_yarascan_dict['ForeignPort'] = entry[5]
            inner_yarascan_dict['State'] = entry[6]
            inner_yarascan_dict['PID'] = entry[7]
            inner_yarascan_dict['Owner'] = entry[8]
            inner_yarascan_dict['Created'] = entry[9]
            outer_yarascan_dict[entry[0]] = inner_yarascan_dict
            all_netscan_list.append(outer_yarascan_dict)

        return all_netscan_list



    #Function: parse_data
    #Parameters: self (this object, with plugin type info), output (data retrieved from a volatility plugin)
    #Description: Parses the volatility data into a dictionaries that can be used to add to a report
    #Returns: output of parsing the specified plugin 
    def parse_data(self,output):
        data = self.tab_parser(output)

        #Returns a list of process dicts
        if self.plugin_type == "windows.pslist.PsList":
            process_data = self.parse_process(data)
            return process_data
        #Returns a list of process dicts
        elif self.plugin_type == "windows.psscan.PsScan":
            return self.parse_process(data)
        elif self.plugin_type == "windows.netscan.NetScan":
            return self.parse_netscan(data)
        elif self.plugin_type == "windows.handles.Handles":
            return self.parse_handles(data)
        elif self.plugin_type == "windows.modules.Modules":
            return self.parse_modules(data)
        elif self.plugin_type == "windows.dlllist.DllList":
            return self.parse_dlllist(data)
        elif self.plugin_type == "windows.cmdline.CmdLine":
            return self.parse_cmdline(data)
        elif self.plugin_type == "windows.svcscan.SvcScan":
            return self.parse_svcscan(data)

            


    

    



