# autoanalyze
# must make sure that pip install yara-python is executed prior
# must use python3
# must specify the volatility path (where is vol.py)


Installation
The installation of AutoVolatile is simple. Here are all the requirements:
Pre-Requirements:
•	Install: Python3
•	Install: python3-pip
•	Install: python3-pip install yara-python
•	Download: Volatility3 https://github.com/volatilityfoundation/volatility3

Usage
The usage of AutoVolatile requires the file path (-l ) of vol.py in the Volatililty 3 folder, as well as a memory image to use (-f). 
Ex. python3 autovolatile.py -f memory.dmp -l “/mnt/c/Users/Cullen/Documents/RIT Course Work/CSEC 759/autovolatile/volatility3/vol.py"
