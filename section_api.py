#This api will be used to associate any data that is related to a specific process
#The idea is that some malicious process must have been started somewhere, which caused other malicious behaviors to begin
#So, we will attempt to place all malicious behaviors that a process may have caused into this object



#Some malicious activities we will attempt to correlate
#1) Network behaviors
#2) DLLs used
#3) Processes spawned
#4) Services created
#5) Files associated
#6) 




class Section:
    def __init__(self, pid, address):
        self.pid = pid
        self.offset = address
        self.network = []
        self.dlls = []
        self.cmdline = []
        self.process_info = []
        self.files = []
        self.services = []
    
    def __str__(self):
        return("pid: " + str(self.pid) + " offset: " + self.offset +\
             " network: " + str(self.network) + " dlls: " + str(self.dlls) \
                 + " process_info: " + str(self.process_info) + " files: " + str(self.files))


    def set_process_info(self, process_data):
        self.process_info = process_data

    #Takes a dictionary and adds to the network list
    def set_network(self, network_data):
        self.network.append(network_data)

    def set_dlls(self, dll_data):
        self.dlls.append(dll_data)

    #def set_processes(self, process_data):
    #    self.processes.append(process_data)

    def set_files(self, file_data):
        self.files.append(file_data)








