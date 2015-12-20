#!/usr/bin/env python3

### vigenere_kf.py
### Encipher a specified file using another file as a key.
### (Originally vigenere.py itself did this, before I moved it to this file.)

import vigenere,os,sys;

# usage
def usage(sname):
	print("Usage:",sname,"MODE INPUT OUTPUT KEYFILE");

# full fledged help
def helpmsg(sname):
	usage(sname);
	print("    MODE     Can be 'encipher', 'decipher', 'encipher_nogz', 'decipher_nogz', or 'help'");
	print("    INPUT    Path to file to en/decipher");
	print("    OUTPUT   Path to write en/deciphered file");
	print("    KEYFILE  Path to key file");

def doMain(mode,inpath,outpath,keypath):
	# check existence of files
	if not os.access(inpath,os.F_OK):
		raise Exception("no such plaintext",inpath);

	# read key
	try:
		keylist=vigenere.getMsg(keypath);
	except FileNotFoundError:
		raise Exception("no such keyfile",keypath);

	# do encipher or decipher
	if mode=="help":
		helpmsg(sys.argv[0]);
	elif mode=="encipher":
		# encipher file
		# (since doEn/DecodeWrite are generators, we must use a for loop;
		# we can safely ignore the values yielded, as they are just status messages)
		for amtdone,curblk,totalblks in vigenere.doEncodeWrite(inpath,outpath,keylist):
			pass;
	elif mode=="decipher":
		# decipher file
		for amtdone,curblk,totalblks in vigenere.doDecodeWrite(inpath,outpath,keylist):
			pass;
	elif mode=="encipher_nogz":
		# encipher file without compressing first
		for amtdone,curblk,totalblks in vigenere.doEncodeWrite(inpath,outpath,keylist,gz=False):
			pass;
	elif mode=="decipher_nogz":
		# decipher file, assume plaintext was not compressed
		for amtdone,curblk,totalblks in vigenere.doDecodeWrite(inpath,outpath,keylist,gz=False):
			pass;
	else:
		# invalid mode, raise error
		raise Exception("no such mode",mode);

def onCmdLine():
	thisis=sys.argv[0];
	# get file paths
	try:
		# mode
		mode=sys.argv[1];
		# source file
		inpath=sys.argv[2];
		# destination file
		outpath=sys.argv[3];
		# key file
		keypath=sys.argv[4];
	except IndexError:
		# user did not enter enough arguments
		if len(sys.argv)>=2:
			# only do this if they entered at least 1 argument
			# otherwise we get an error
			if mode=="help":
				# they entered "help" as the first argument, show help and exit
				helpmsg(thisis);
				exit(0);
		# otherwise, show usage and exit
		usage(thisis);
		print("Try '"+thisis+" help' for more information.");
		exit(2);
	try:
		# try to run encipher/decipher
		doMain(mode,inpath,outpath,keypath);
	except Exception as exc:
		# doMain() raised exception, what went wrong?
		excstr=exc.args[0];
		if excstr.startswith("no such mode"):
			# invalid mode argument
			usage(thisis);
			print("Invalid mode argument; can only be 'encipher', 'decipher',\
			'encipher_nogz', 'decipher_nogz', or 'help'");
			exit(2);
		elif excstr.startswith("no such plaintext"):
			# input file does not exist
			print("File to encipher given does not exist.");
		elif excstr.startswith("no such keyfile"):
			# key file does not exist
			print("Key file given does not exist.");
		elif excstr.startswith("zero-length key"):
			# zero length key given
			print("Key file given is zero bytes long.");
		elif excstr.find("while decompressing")>-1:
			# invalid key
			print("Key file given does not match the one used to encipher the file.");
		else:
			# something else, display the exception
			print(str(exc));
		# regardless of what went wrong, exit with nonzero status
		exit(1);

# invoke onCmdLine() if we are executing directly
if __name__=="__main__":
	onCmdLine();