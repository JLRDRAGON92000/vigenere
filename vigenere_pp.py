#!/usr/bin/env python3

### vigenere_pp.py
### Enciphers a file using a randomly generated key, which is in turn
### enciphered with a user-specified passphrase and written to a separate file.
### Requires that os.urandom() / random.SystemRandom be available on your platform.

import vigenere,os,sys;
from getpass import getpass;

# key file extension
KEY_SUFFIX=".key";

# usage
def usage(sname):
	print("Usage:",sname,"MODE INPUT OUTPUT [KEYSTRENGTH]");

# full fledged help
def helpmsg(sname):
	usage(sname);
	print("    MODE         Can be 'encipher', 'decipher', or 'help'");
	print("    INPUT        Path to file to en/decipher");
	print("    OUTPUT       Path to write en/deciphered file");
	print("    KEYSTRENGTH  Number of characters to use in the generated key; only required when mode is 'encipher'");

# encipher file
def encode(ipath,opath,keypath,keystrength):
	# generate key
	randkey=os.urandom(keystrength);
	# encipher and write file (since doEncodeWrite is a generator now, use a for loop)
	# (we don't really care about the status messages here)
	for amtdone,curblk,totalblks in vigenere.doEncodeWrite(ipath,opath,randkey):
			print("[VIGENERE] Enciphering: {0:.2f}% done (block {1:d} of {2:d})".format(amtdone*100,curblk,totalblks),file=sys.stderr);
	# interactively prompt for passphrase to protect key
	passwd=bytes(getpass("Passphrase to encipher key with: "),"utf-8");
	# disallow zero length passphrase
	if len(passwd)<=0:
		# passphrase is zero bytes long, exit
		print("Zero-length passphrase not allowed.");
		exit(1);
	# request passphrase again
	pwconf=bytes(getpass("Enter same passphrase again: "),"utf-8");
	# make sure the two passphrases match
	if passwd!=pwconf:
		# they don't, exit
		print("Passphrases do not match.");
		exit(1);
	
	# write protected key
	ofile=open(keypath,"wb");
	ofile.write(vigenere.doDataEncode(randkey,passwd));
	ofile.close();
	# write confirmation
	print("File",ipath,"enciphered successfully");
	print("Key is the file's name with '"+KEY_SUFFIX+"' appended at the end, in this case:",keypath);

# decipher file
def decode(ipath,opath,keypath):
	# was keyfile included?
	if not os.access(keypath,os.F_OK):
		# it wasn't, raise error
		raise FileNotFoundError("This file has no associated key. Keep in mind that the key file's name\nis the enciphered file's name with '"+KEY_SUFFIX+"' appended to it.");
	# prompt for passcode
	passwd=bytes(getpass("Passphrase used to encipher key: "),"utf-8");
	# read in and decipher key
	keyfile=open(keypath,"rb");
	randkey=vigenere.doDataDecode(keyfile.read(),passwd);
	keyfile.close();
	# attempt to decipher file
	try:
		# decipher and write out file
		for amtdone,curblk,totalblks in vigenere.doDecodeWrite(ipath,opath,randkey):
			print("[VIGENERE] Deciphering: {0:.2f}% done (block {1:d} of {2:d})".format(amtdone*100,curblk,totalblks),file=sys.stderr);
	except TypeError as err:
		# TypeError: most likely, doDataDecode internally returned None
		# due to invalid zlib header, indicating the passphrase is incorrect
		if err.args[0].startswith("object of type 'NoneType'"):
			# doDataDecode returned None, user's passphrase is incorrect
			print("Passphrase is incorrect.");
		else:
			# something else went wrong
			print(str(err));
		# either way, exit with nonzero status
		exit(1);
	# write confirmation
	print(ipath,"deciphered successfully");
	print("The deciphered file is:",opath);

# command line mode, accept arguments
def onCmdLine():
	# name of our script
	thisis=sys.argv[0];
	# get mode and file path arguments
	mode=None;
	try:
		# mode
		mode=sys.argv[1];
		# source path
		inpath=sys.argv[2];
		# destination path
		outpath=sys.argv[3];
	except IndexError:
		# the user entered less than 3 arguments
		if mode=="help":
			# they entered "help" as the first argument, show the help and exit
			helpmsg(thisis);
			exit(0);
		# otherwise, show usage message and exit with nonzero status
		usage(thisis);
		print("Try '"+thisis+" help' for more information.");
		exit(2);
	# handle mode argument
	if mode=="help":
		# redundant check for help mode, as user may have entered 3 or more arguments
		helpmsg(thisis);
		exit(0);
	if mode=="encipher":
		# enciphering mode: encipher source file and write out to file
		# note: the 4th argument ("KEYSTRENGTH") is required here
		try:
			# get key length
			keystrength=int(sys.argv[4]);
		except IndexError:
			# show usage, along with a note stating that KEYSTRENGTH is required when enciphering
			usage(thisis);
			print("KEYSTRENGTH is required when using encoding mode.");
			exit(2);
		# encipher the file
		# (the key file's name is the ciphertext file's name with '.key' appended to the end)
		encode(inpath,outpath,(outpath+KEY_SUFFIX),keystrength);
	elif mode=="decipher":
		# decipher the specified ciphertext file
		decode(inpath,outpath,(inpath+KEY_SUFFIX));
	else:
		# invalid mode, show usage
		usage(thisis);
		print("Invalid mode argument; can only be 'encipher', 'decipher', or 'help'");

if __name__=="__main__":
	onCmdLine();
