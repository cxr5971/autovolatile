import argparse
import subprocess
from vol_bot import Vol_Bot

def execute_pslist(vol_engine):
    #pslist_output = subprocess.run(["volatility", ], capture_output=True, text=True)
    return


def execute_psscan(vol_engine):
    return







def execute_psxview(vol_engine):
    return





#
def execute_process_finder(vol_engine):
    return


#def determine_profile(vol_engine):
#    profile_output = subprocess.run([vol_engine.vol_loc, vol_engine.memory_file, "kdbgscan"], capture_output=True, text=True)
#    print(profile_output)


def main():
    parser = argparse.ArgumentParser(description='Autovolatile Stuff')
    parser.add_argument('-l', '--location', action='store', required=True)
    parser.add_argument('-f', '--file', action='store')
    parser.add_argument('-p', '--profile', action='store')
    args = parser.parse_args()

    vol_engine = Vol_Bot(args.profile, args.file, args.location)
    
    if vol_engine.profile == None:
        determine_profile(vol_engine)





if __name__ == '__main__':
    main()