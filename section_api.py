
#Author: Cullen Rezendes
#Class Name: Section
#Description: Section is a module designed to store volatility data separated by process

class Section:
    def __init__(self, pid, address):
        self.pid = pid
        self.offset = address
        self.name = ""
        self.network = []
        self.dlls = []
        self.cmdline = []
        self.process_info = []
        self.files = []
        self.services = []
        self.handles = []
    
    #Returns string representation of a section
    def __str__(self):
        return("pid: " + str(self.pid) + " offset: " + self.offset +\
             " network: " + str(self.network) + " dlls: " + str(self.dlls) \
                 + " process_info: " + str(self.process_info) + " files: " + str(self.files))

    #Simple function to set process_info, not actually needed, could just directly access the variable
    def set_process_info(self, process_data):
        self.process_info = process_data









