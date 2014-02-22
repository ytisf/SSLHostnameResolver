#!/usr/bin/env python

import sys
import os
import iptools
import socket
import M2Crypto
from optparse import OptionParser


def getCertificate(site):
	cert = ssl.get_server_certificate((site, 443))
	x509 = M2Crypto.X509.load_cert_string(cert)
	x509.get_subject().as_text()
	return x509.get_subject().as_text()

def getArgvs():
    parser = OptionParser()
    parser.add_option("-r", "--range", dest="targets", default='', help="Range to get SSL certs from.")
    (options, args) = parser.parse_args()
    return options

def rangeToarray(iprange):
	length = len(iptools.IpRangeList(iprange))
	array = str(iptools.IpRangeList(iprange))
	return (length, array)

def main():
	print ''
	arguments = getArgvs()

	if arguments.targets == "":
		sys.exit("Must provide at least one host to scan.")

	try:
		targets = iptools.IpRangeList(arguments.targets)
		for ip in targets:
			try:
				a = getCertificate(ip)
			else:
				print ip +' - problem with connecting to 443 to get cert.'
			f = open(ip + '.pem', 'wb')
			f.write(a)
			f.close()
	except:
		print "The IP range: " + arguments.targets + " is not a valid one."

if __name__ == "__main__":
    main()