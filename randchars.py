#!/usr/bin/env python3

### randchars.py
### Generates random bytes and writes them to a file.
### Requires that os.urandom() be available.

import os;
import sys;

# usage
def usage(sname):
	print("Usage:",sname,"NUMCHARS [OUTPUT]");

# full fledged help
def helpmsg(sname):
	usage(sname);
	print("    NUMCHARS  Number of characters to generate");
	print("    OUTPUT    Path to a file to write random characters to");

# generate random characters
def doRandChars(howmany):
	# return bytes from system random device
	return bytes(os.urandom(howmany));

# command line mode, accept arguments
def onCmdLine():
	# name of this script
	thisis=sys.argv[0];
	# path to file
	fpath=None;
	# whether to write a file
	writeoutfile=True;
	# if the user did not specify a file path, don't write a file
	try:
		fpath=sys.argv[2];
	except IndexError:
		writeoutfile=False;
	
	# how many bytes to generate?
	try:
		howmany=int(sys.argv[1]);
	except IndexError:
		# user did not provide this argument
		usage(thisis);
		exit(2);
	except ValueError:
		# user typed 'help' or other invalid value
		if sys.argv[1]=="help":
			# user typed 'help'
			helpmsg(thisis);
			exit(0);
		else:
			# user typed some other non-number
			print("First argument is not a number");
			usage(thisis);
			exit(2);
	print("Writing",howmany,"random bytes to",(fpath or "stdout"));
	# generate bytes
	byteset=doRandChars(howmany);
	# write out (to file if desired)
	if writeoutfile:
		# write to file
		ofile=open(fpath,"wb");
		ofile.write(byteset);
		ofile.close();
	else:
		# write to stdout
		print(byteset);

if __name__=="__main__":
	onCmdLine();
