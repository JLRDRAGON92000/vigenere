#!/usr/bin/env python3

### vigenere.py
### A modified Vigenere cipher using a 256-character x 256-character tabula recta.

### General process for enciphering a file:
### 1. The plaintext message is read from a file specified by the user.
### 2. The key is transformed and extended:
###    2.1. A SHA-512 hash of the key is used to seed a random number generator,
###         which is used to generate part of the final key.
###    2.2. The resulting key part is added to the final key, and its
###         SHA-512 hash is used to seed the random number generator
###         for the next round of key transformation.
###    2.3. Steps 3.1 and 3.2 are repeated until the key is as long or longer
###         than the message.
###    2.4. Once the final key is as long as or longer than the message,
###         it is cut down to the length of the message and returned.
### 3. The message and the key are broken down into 8-kilobyte blocks.
### 4. A handle is opened to the destination file specified by the user.
### 5. Each block is enciphered separately:
###    5.1. A unique substitution table is generated using Python's deterministic random
###         number generator, seeded with the SHA-512 hash of the key.
###    5.2. Each byte in the message block is added with its corresponding byte in
###         the key block.
###    5.3. The modulo operator is applied to the result of 6.2, by 256.
###    5.4. The resulting ciphertext byte is the byte at the 6.3th position in the
###         substitution table.
###    5.5. The ciphertext block is written to the destination file.
### 6. The destination file is closed.

### General process for deciphering a file:
### 1. The ciphertext message is read from a file specified by the user.
### 2. The key is transformed and extended, as in step 3 above.
### 3. The ciphertext and the key are broken down into 8-kilobyte blocks.
### 4. A handle is opened to the destination file specified by the user.
### 5. Each block is deciphered separately:
###    5.1. A unique substitution table is generated using Python's deterministic random
###         number generator, seeded with the SHA-512 hash of the key.
###    5.2. Each byte in the key block is subtracted from its corresponding byte in
###         the ciphertext block.
###    5.3. The resulting byte is used to address the substitution table. The result
###         is the byte at the corresponding position in the substitution table.
###    5.4. The corresponding byte in the plaintext block is the result of 5.3,
###         modulo 256.
###    5.5. The plaintext block is written to the destination file.
### 6. The destination file is closed.

import os,zlib;
from math import ceil;
from hashlib import sha512;
from random import seed,getrandbits,shuffle;
from time import perf_counter;

# size of blocks
BLKSIZE=8192;

# universal ctable start point (ints 0-255 in order)
UCTABLE=tuple(n for n in range(256));

# exceptions
# zero length key
class ZeroKeyException(Exception): pass;
# zero length value (such as a file path)
class ZeroValException(Exception): pass;

# extend and trim a key, transforming each subsequent copy
def extTrimKey(key,glen):
	""" Preprocess a key for enciphering or deciphering; extend it to the length of the message,
	pseudo-randomly transforming each part of the key
	:param key: Key to process
	:param glen: Length to make the final key
	:return: The key, extended and trimmed to the desired length
	"""
	# key to be returned
	keyfinal=b"";
	# start with initial key value
	keypart=key;
	for i in range(ceil(glen/len(key))):
		# transform this copy of the key
		# hash last key part and seed random number generator
		seed(sha512(keypart).digest());
		# generate new key part
		keypnum=getrandbits(len(keypart)*8);
		# hex format random number to extract bytes
		keyphex=("{0:0>"+str(len(keypart)*2)+"x}").format(keypnum);
		# make key part
		keypart=bytes.fromhex(keyphex);
		# add it to existing key
		keyfinal+=keypart;
	# trim key to message length
	keyfinal=keyfinal[:glen];
	# return result
	return keyfinal;

# read and return message from file
def getMsg(ipath):
	""" Read and return the contents of the file at the given path.
	:param ipath: Path to file containing message
	:return: Message read from file
	"""
	ifile=(os.access(ipath,os.F_OK) and open(ipath,"rb") or None);
	if not ifile:
		raise FileNotFoundError("file not found",ipath);
	ifile.seek(0);
	msgnc=bytes(ifile.read());
	ifile.close();
	return msgnc;

# encipher a single byte (call for map())
def doIntEncode(msgb,keyb,ctable):
	return ctable[(msgb+keyb)%256];

# decipher a single byte (call for map())
def doIntDecode(msgb,keyb,rctable):
	return (rctable[msgb]-keyb)%256;

# encipher binary data string directly
# message is no longer compressed by default
# (or at all)
def doDataEncode(msg,key,gz=False,skipextkey=False):
	""" Encipher and return msg using the given key.
	if gz is true, the message is zlib-compressed before being enciphered.
	:param msg: Message to encipher
	:param key: Key to encipher message with
	:param gz: Whether message should be compressed before enciphering
	:param skipextkey: Whether to not extend and trim the key received (for use by doEncodeWrite)
	:return: Enciphered message
	"""
	# is key zero-length?
	if len(key)<=0:
		# if so, error
		raise ZeroKeyException("zero-length key");
	# compress message and measure length
	if gz:
		msg=zlib.compress(msg);
	msglen=len(msg);
	# seed RNG with hash of key
	seed(sha512(key).digest());
	# generate ctable mappings by shuffling ints 0-255 in pseudorandom order decided by key
	thisctable=list(UCTABLE);
	shuffle(thisctable);
	# extend and trim key if specified
	if not skipextkey:
		key=extTrimKey(key,msglen);
	# encipher message
	# (now using doIntEncode() and a for loop, to allow passing of ctable)
	encoded=b"";
	for mb,kb in zip(msg,key):
		encoded+=bytes([doIntEncode(mb,kb,thisctable)]);
	# return enciphered message
	return encoded;

# decipher binary data string directly
def doDataDecode(msg,key,gz=False,skipextkey=False):
	""" Decipher and return msg using the given key.
	If gz is True, it is assumed the resulting plaintext is zlib-compressed.
	:param msg: Message to decipher
	:param key: Key to decipher message with
	:param gz: Whether deciphered message has been compressed
	:param skipextkey: Whether to not extend and trim the key received (for use by doEncodeWrite)
	:return: Deciphered message
	"""
	# is key zero-length?
	if len(key)<=0:
		# if so, error
		raise ZeroKeyException("zero-length key");
	# get message and length
	msglen=len(msg);
	# seed RNG with hash of key
	seed(sha512(key).digest());
	# generate ctable mappings by shuffling ints 0-255 in pseudorandom order decided by key
	thisctableval=list(UCTABLE);
	shuffle(thisctableval);
	# zip original and shuffled ctable mappings
	thisctable=dict(zip(thisctableval,UCTABLE));
	# extend and trim key if specified
	if not skipextkey:
		key=extTrimKey(key,msglen);
	# decipher message
	# (now using doIntDecode() and a for loop, to allow passing of ctable)
	decoded=b"";
	for mb,kb in zip(msg,key):
		decoded+=bytes([doIntDecode(mb,kb,thisctable)]);
	# uncompress final message and return
	try:
		return (gz and bytes(zlib.decompress(decoded)) or decoded);
	except zlib.error:
		return None;

# preprocess message and key for doEn/DecodeWrite()
def msgKeyPreprocess(msg,key):
	""" Do some preprocessing on the message and key
	prior to their use in doEncodeWrite() or doDecodeWrite().
	:param msg: Message to preprocess
	:param key: Key to preprocess
	:return: List of message blocks, list of key blocks
	"""
	# break message and key into 8k blocks; extend the key each round
	msgblks=[];
	keyblks=[];
	# start with the key itself
	thiskeyblk=key;
	# iterate over range of indexes (start at block size, increment by block size each block)
	for i in range(BLKSIZE,len(msg)+BLKSIZE,BLKSIZE):
		# append a block of message data
		msgblks.append(msg[i-BLKSIZE:i]);
		# extend and transform a block of key data
		thiskeyblk=extTrimKey(thiskeyblk[len(thiskeyblk)-len(key):],BLKSIZE);
		# append the block of transformed key data
		keyblks.append(thiskeyblk);
	# return blocks
	return msgblks,keyblks;

# encipher file and write out to other file
def doEncodeWrite(ipath,opath,key,gz=False):
	""" Encipher the file at ipath using the given key, and write the results to the file at opath.
	:param ipath: Path to file to encipher
	:param opath: Path to write enciphered file to
	:param key: Key to encipher file with
	:param gz: Whether to compress received message before enciphering it
	:return: Yields its progress as a float, int, and int
	"""
	# start timer
	starttime=perf_counter();
	# get message and length
	msg=getMsg(ipath);
	# perform check for zero length output file path
	# (zero length input path will get caught when
	# trying to read the file)
	if len(ipath)<=0 or len(opath)<=0:
		raise ZeroValException("empty output file field");
	# preprocess message and key
	msgblks,keyblks=msgKeyPreprocess(msg,key);
	# determine how often to show status messages (typically, for longer texts, 20 will be shown in total)
	blkstathowoften=len(msgblks)//20;
	if blkstathowoften<=0:
		blkstathowoften=1;
	# encode and write message one 8k block at a time
	ofile=open(opath,"wb");
	for it,blk in enumerate(msgblks):
		# encipher a single block
		blkenc=doDataEncode(blk,keyblks[it],gz,skipextkey=True);
		# write block to file
		ofile.write(blkenc);
		# yield status at each specified interval
		if it%blkstathowoften==0:
			# how much have we done? (%)
			amtdone=it/len(msgblks);
			# yield that percentage, the current block index, and the number of blocks
			yield amtdone,it,len(msgblks);
	# we are finished, one more status message indicating 100% completion for good measure
	yield 1,len(msgblks),len(msgblks);
	# print("[VIGENERE] 100.00% done (block {0:d} of {0:d})".format(len(msgblks)));
	# get time it took to encipher
	completiontime=perf_counter();
	tdelta=completiontime-starttime;
	ofile.close();
	print("[{0: >8.8f}] [VIGENERE] Enciphering took {1:.8f} seconds.".format(perf_counter(),tdelta));

# decipher file and write to other file
def doDecodeWrite(ipath,opath,key,gz=False):
	""" Decipher the file at ipath using the given key, and write the results to the file at opath.
	:param ipath: Path to file to decipher
	:param opath: Path to write deciphered file to
	:param key: Key to decipher file with
	:param gz: Whether the received message was compressed prior to enciphering
	:return: Yields its progress as a float, int, and int
	"""
	# start timer
	starttime=perf_counter();
	# get message and length
	msg=getMsg(ipath);
	# perform check for zero length output file path
	# (zero length input path will get caught when
	# trying to read the file)
	if len(ipath)<=0 or len(opath)<=0:
		raise ZeroValException("empty output file field");
	# preprocess message and key
	msgblks,keyblks=msgKeyPreprocess(msg,key);
	# determine how often to show status messages (20 will be shown in total)
	blkstathowoften=len(msgblks)//20;
	if blkstathowoften<=0:
		blkstathowoften=1;
	# decode and write message one 8k block at a time
	ofile=open(opath,"wb+");
	for it,blk in enumerate(msgblks):
		# decipher a single block
		blkdec=doDataDecode(blk,keyblks[it],gz,skipextkey=True);
		# write block to file
		ofile.write(blkdec);
		# yield status at each specified interval
		if it%blkstathowoften==0:
			# how much have we done? (%)
			amtdone=it/len(msgblks);
			# yield that percentage, the current block index, and the number of blocks
			yield amtdone,it,len(msgblks);
	# we are finished, one more status message indicating 100% completion for good measure
	yield 1,len(msgblks),len(msgblks);
	# get time it took to decipher
	completiontime=perf_counter();
	tdelta=completiontime-starttime;
	ofile.close();
	print("[{0: >8.8f}] [VIGENERE] Deciphering took {1:.8f} seconds.".format(perf_counter(),tdelta));

# the user may have attempted to run this directly, so display a warning if they did
if __name__=="__main__":
	# write warning
	print("This is just a library.");
	print("Perhaps you meant to try one of the available frontends to it:");
	# get files starting with 'vigenere_'
	for fname in os.listdir():
		if fname.startswith("vigenere_") and (fname.endswith(".py") or fname.endswith(".pyw")):
			print("    "+fname);
