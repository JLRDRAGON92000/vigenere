#!/usr/bin/env python3

### vigenere_ppg.pyw
### Graphical equivalent of vigenere_pp.py.
### Requires that os.urandom() / random.SystemRandom be available on your platform.

import vigenere,os,sys;
import graphics_o as g;
from traceback import print_exc;
from time import perf_counter;
from datetime import datetime;

# key file extension
KEY_SUFFIX=".key";
# window title
TITLE_DEF="Vigenere En/Decipher Demo";

# whether or not we should point stdout at a log file
logfile=True;
# if specified open logfile and redirect stdout to it
if logfile:
	logfile=open(sys.argv[0]+".log","a");
	sys.stdout=logfile;
	sys.stderr=logfile;

# start performance counter
perf_counter();

# encipher file
def encode(ipath,opath,keypath,passwd,keystrength):
	# does plaintext exist?
	# (normally doEncodeWrite would do this check, but
	# if keystrength is incorrect, key generation will
	# raise ValueError before the check can occur, and
	# the user will see the 'Invalid key strength' error
	# first, instead of the 'file not found' error)
	if not (os.access(ipath,os.F_OK)):
		# error if not
		raise FileNotFoundError("file not found",ipath);
	# catch blank passphrase
	# (we must do this now, otherwise the file will be enciphered without
	# the key being written to file)
	if len(passwd)<=0:
		raise vigenere.ZeroKeyException("zero-length passphrase");
	# generate key (raise ValueError if key strength is not valid as an integer literal)
	randkey=os.urandom(int(keystrength));
	# encipher file and yield back status messages
	yield from vigenere.doEncodeWrite(ipath,opath,randkey);
	# write protected key
	ofile=open(keypath,"wb");
	ofile.write(vigenere.doDataEncode(randkey,passwd));
	ofile.close();

# decipher file
def decode(ipath,opath,keypath,passwd):
	# does ciphertext exist?
	if not os.access(ipath,os.F_OK):
		# error if not
		raise FileNotFoundError("file not found",ipath);
	# was keyfile included?
	if not os.access(keypath,os.F_OK):
		# error if not
		raise FileNotFoundError("This file has no associated key");
	# decipher key
	keyfile=open(keypath,"rb");
	randkey=vigenere.doDataDecode(keyfile.read(),passwd);
	keyfile.close();
	# decipher file and yield back status messages
	yield from vigenere.doDecodeWrite(ipath,opath,randkey);

### GUI functions begin here ###

# Check if a point is within a rectangle
def isInRect(pt,rect):
	# get Rectangle points
	rectp1=rect.getP1();
	rectp2=rect.getP2();
	# check if pt is in boundaries
	return (
		rectp1.getX()<pt.getX()<rectp2.getX()
		and rectp1.getY()<pt.getY()<rectp2.getY()
	);

# Create, draw, and return a reference to an Entry object
def mkdrawentry(center,length,win,colour=None):
	# initialise Entry
	thisentry=g.Entry(center,length);
	if colour:
		# set text colour if specified
		thisentry.setTextColor(colour);
	# draw to window
	thisentry.draw(win);
	# return the final object
	return thisentry;

# Create, draw, and return a reference to a button (A Rectangle with some Text on it)
def mkdrawbutton(p1,p2,colour,label,win):
	# initialise Rectangle
	thisbtn=g.Rectangle(p1,p2);
	# set fill colour if specified
	thisbtn.setFill(colour);
	# draw to window
	thisbtn.draw(win);
	# draw label
	g.Text(thisbtn.getCenter(),label).draw(win);
	# return the final object
	return thisbtn;

# Main graphics handler
def doGuiMain(win):
	# Encipher interface
	# Title
	g.Text(g.Point(60,30),"Encipher").draw(win);
	# File to encipher
	g.Text(g.Point(80,60),"Input file").draw(win);
	entryEIFile=mkdrawentry(g.Point(333,60),40,win);
	# File to write out
	g.Text(g.Point(85,90),"Output file").draw(win);
	entryEOFile=mkdrawentry(g.Point(333,90),40,win)
	# Key strength
	g.Text(g.Point(95,120),"Key strength").draw(win);
	entryEKeylen=mkdrawentry(g.Point(180,120),6,win);
	# Passphrase
	g.Text(g.Point(265,120),"Passphrase").draw(win);
	entryEPassphrase=mkdrawentry(g.Point(414,120),22,win,"gray");
	# Encipher button
	btnEncipher=mkdrawbutton(g.Point(560,60),g.Point(680,120),"#FF4C4C","Encipher",win);
	
	# Decipher interface
	# Title
	g.Text(g.Point(60,150),"Decipher").draw(win);
	# File to decipher
	g.Text(g.Point(80,180),"Input file").draw(win);
	entryDIFile=mkdrawentry(g.Point(333,180),40,win);
	# File to write out
	g.Text(g.Point(85,210),"Output file").draw(win);
	entryDOFile=mkdrawentry(g.Point(333,210),40,win);
	# Passphrase
	g.Text(g.Point(94,240),"Passphrase").draw(win);
	entryDPassphrase=mkdrawentry(g.Point(333,240),40,win,"gray");
	# Decipher button
	btnDecipher=mkdrawbutton(g.Point(560,180),g.Point(680,240),"#4CFF4C","Decipher",win);
	
	# Clear form button
	btnClear=mkdrawbutton(g.Point(560,130),g.Point(680,170),"orange","Clear fields",win);
	
	# Status message
	labelStatmsg=g.Text(g.Point(360,280),"Initialising...");
	labelStatmsg.setTextColor("orange");
	labelStatmsg.draw(win);
	# Update status message
	def updatestat(text,color):
		# update the shown status message
		labelStatmsg.setTextColor(color);
		labelStatmsg.setText(text);
		# log the status message with timestamp
		print("[{0: >8.8f}] [VIGENERE] Stat msg: {1}".format(perf_counter(),text));
	# Update window title with a prefix in [] ([ERROR] or [WORKING] or [DONE])
	def titlepfix(win,prefix=None):
		ftitle=(prefix and "["+prefix.upper()+"] " or "")+TITLE_DEF;
		win.master.title(ftitle);
	
	# initialising finished, update status and write to logfile
	print("[{0: >8.8f}] [VIGENERE] Successful initialisation at {1}".format(perf_counter(),datetime.now().isoformat()));
	updatestat("Ready","green");
	
	# Click handler
	while True:
		# Get click
		click=win.getMouse();
		# Handle click on button
		if isInRect(click,btnEncipher):
			# Encipher button clicked, encipher and update status
			try:
				# Change status message to orange "enciphering in progress"
				updatestat("Enciphering in progress...","orange");
				# Prefix window title: "[WORKING]"
				titlepfix(win,"working");
				# Call encode() to do the actual enciphering; it will yield back doEncodeWrite()'s status messages
				for amtdone,curblk,totalblks in encode(
					entryEIFile.getText(),
					entryEOFile.getText(),
					entryEOFile.getText()+KEY_SUFFIX,
					bytes(entryEPassphrase.getText(),"utf-8"),
					entryEKeylen.getText()
				):
					# update status message with new status yield
					updatestat("Enciphering: {0:.2f}% done (block {1:d} of {2:d})".format(amtdone*100,curblk,totalblks),"orange");
				# Change status message to green "file enciphered"
				updatestat("File "+entryEIFile.getText()+" enciphered as "+entryEOFile.getText()+", using key "+entryEOFile.getText()+KEY_SUFFIX,"green");
				# Prefix window title: "[DONE]"
				titlepfix(win,"done");
			# Errors
			# For all handled errors, procedures are as follows:
			#	Write red status message describing the error
			#	Prefix window title: "[ERROR]"
			except FileNotFoundError:
				# FileNotFoundError: Specified input file not found
				updatestat("Input file not found","red");
				titlepfix(win,"error");
			except vigenere.ZeroValException:
				# ZeroValException: Output file path was zero bytes long
				updatestat("No value entered for output file","red");
				titlepfix(win,"error");
			except vigenere.ZeroKeyException:
				# ZeroKeyException: Passphrase was zero bytes long
				updatestat("No value entered for passphrase","red");
				titlepfix(win,"error");
			except ValueError:
				# ValueError: int() could not parse provided key strength
				updatestat("No or invalid value entered for key strength","red");
				titlepfix(win,"error");
			except Exception:
				# Catch all for exceptions not caught above
				updatestat("Unknown error, see log for details","red");
				titlepfix(win,"error");
				# Write exception info and traceback
				print("[{0: >8.8f}] [VIGENERE] Exception during enciphering:".format(perf_counter()));
				print_exc();
		
		elif isInRect(click,btnDecipher):
			# Decipher button clicked, decipher and update status
			try:
				# Change status message to orange "deciphering in progress"
				updatestat("Deciphering in progress...","orange");
				# Prefix window title: "[WORKING]"
				titlepfix(win,"working");
				# Call decode() to do the actual deciphering; it will yield back doDecodeWrite()'s status messages
				for amtdone,curblk,totalblks in decode(
					entryDIFile.getText(),
					entryDOFile.getText(),
					entryDIFile.getText()+KEY_SUFFIX,
					bytes(entryDPassphrase.getText(),"utf-8")
				):
					# update status message with new status yield
					updatestat("Deciphering: {0:.2f}% done (block {1:d} of {2:d})".format(amtdone*100,curblk,totalblks),"orange");
				# Change status message to green "file <ciphertext> deciphered as <new plaintext>"
				updatestat("File {0} deciphered as {1}".format(entryDIFile.getText(),entryDOFile.getText()),"green");
				# Prefix window title: "[DONE]"
				titlepfix(win,"done");
			# Errors (procedures same as above)
			except FileNotFoundError as err:
				# FileNotFoundError: One of two things; either...
				if err.args[0].startswith("This file has no associated key"):
					# ...the key file corresponding to our input was not found...
					updatestat("File's associated key not found; should be: "+entryDIFile.getText()+KEY_SUFFIX,"red");
				else:
					# ...or the input was not found.
					updatestat("Input file not found","red");
				titlepfix(win,"error");
			except TypeError:
				# TypeError: A call to doDataDecode returned None; usually this means the passphrase is incorrect
				updatestat("Passphrase is incorrect","red");
				titlepfix(win,"error");
			except vigenere.ZeroValException:
				# ZeroValException: Output field is blank
				updatestat("No value entered for output file","red");
				titlepfix(win,"error");
			except vigenere.ZeroKeyException:
				# ZeroKeyException: Key provided was zero bytes long
				updatestat("Key provided was zero bytes long, or passphrase field is empty","red");
				titlepfix(win,"error");
			except Exception:
				# Catch all for exceptions not caught above
				updatestat("Unknown error, see log for details","red");
				titlepfix(win,"error");
				# Write exception info and traceback
				print("[{0: >8.8f}] [VIGENERE] Exception during deciphering:".format(perf_counter()),file=sys.stderr);
				print_exc();
		elif isInRect(click,btnClear):
			# Clear all fields
			# Encipher fields
			entryEIFile.setText("");
			entryEOFile.setText("");
			entryEKeylen.setText("");
			entryEPassphrase.setText("");
			# Decipher fields
			entryDIFile.setText("");
			entryDOFile.setText("");
			entryDPassphrase.setText("");
			# Reset status message
			updatestat("Ready","green");
			# Reset window title
			titlepfix(win);
		# flush logfile buffer
		logfile.flush();

# main
if __name__=="__main__":
	# initialise main graphics window
	gwin=g.GraphWin(TITLE_DEF,720,300);
	# start actual program
	try:
		doGuiMain(gwin);
	except g.GraphicsError as err:
		if err.args[0].startswith("getMouse in closed window"):
			print("[{0: >8.8f}] [VIGENERE] Window closed, exiting.".format(perf_counter()),file=sys.stderr);
		else:
			print("[{0: >8.8f}] [VIGENERE] Graphics exception:".format(perf_counter()),file=sys.stderr);
			print_exc();
	except KeyboardInterrupt as err:
		print("[{0: >8.8f}] [VIGENERE] Keyboard interrupt sent, exiting.".format(perf_counter()),file=sys.stderr);
	except Exception as err:
		print("[{0: >8.8f}] [VIGENERE] Fatal exception:".format(perf_counter()),file=sys.stderr);
		print_exc();
	finally:
		if logfile:
			print("[{0: >8.8f}] [VIGENERE] End of this run.".format(perf_counter()),);
			print("-"*40);
			logfile.close();
		exit(0);
