

import optparse
import nmap
from socket import *

def nmapScan(tgtHost, tgtPort):
	tgtIP = gethostbyname(tgtHost)
	nScan = nmap.PortScanner()
	nScan.scan(tgtIP, tgtPort)
	state = nScan[tgtIP]['tcp'][int(tgtPort)]['state']
	print " [*] " + tgtHost + " tcp/" +tgtPort + " " + state

def Main():
	parser = optparse.OptionParser('usage %prog '+\
		'-H <target host> -p <target port>')
	parser.add_option('-H', dest='tgtHost', type='string', \
		help='specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', \
		help='specify target port[s] seperated by comma')
	(options, args) = parser.parse_args()
	if (options.tgtHost == None) | (options.tgtPort == None):
		print parser.usage
		exit(0)
	else:
		tgtHost = options.tgtHost
		tgtPorts = str(options.tgtPort).split(',')

	for tgtPort in tgtPorts:
		nmapScan(tgtHost, tgtPort)

if __name__ == '__main__':
	Main()



