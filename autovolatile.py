import argparse
import subprocess

def execute_pslist(memory_file, profile):
    pslist_output = subprocess.run(["volatility", profile,], capture_output=True, text=True)



def execute_psscan(memory_file):
    return







def execute_psxview(memory_file):
    return





#
def execute_process_finder(memory_file):
    return


def determine_profile(memory_file):
    profile_output = subprocess.run(["volatility", ], capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description='Autovolatile Stuff')
    parser.add_argument('-f', '--file', action='store')
    args = parser.parse_args()







    #profile = "--profile " + profile_found












if __name__ == '__main__':
    main()