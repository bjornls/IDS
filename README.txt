An Intrusion Detection System written in Python.

Please note that this is a university project written within a small timeframe, and with number of other deadlines. The software is written from scratch with no major guidelines. The Network_Security_2.pdf provides some documentation for the overall functionality.




Bjorn Sigurbergsson


To install:

0: sudo apt install python-pip
1: sudo pip install pcapy

To run (python 2.7):

for live capturing
	
	python main.py <config file>

where <config file> is e.g. conf.xml

for reading from pcap file

	python main.py <config file> <pcap file>

where pcap file is e.g. arpdump.pcap

so an example execution would be 

	python main.py conf.xml arpdump.pcap

The unit tests can be run with

python -m unittest tests.py


