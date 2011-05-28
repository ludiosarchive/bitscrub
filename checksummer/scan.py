"""
Some useful documentation:

How To Use NTFS Alternate Data Streams
http://support.microsoft.com/kb/105763

File Times
http://msdn.microsoft.com/en-us/library/ms724290%28v=vs.85%29.aspx

CreateFile
http://msdn.microsoft.com/en-us/library/aa363858%28v=vs.85%29.aspx

How To Use NTFS Alternate Data Streams
http://support.microsoft.com/kb/105763

File Streams
http://msdn.microsoft.com/en-us/library/aa364404%28v=vs.85%29.aspx
"""

from __future__ import with_statement

import os
import stat
import sys
import struct
import time
import datetime
import operator
import argparse
import winnt
import ctypes
import hashlib
from collections import namedtuple

import win32file

try:
	from twisted.python.filepath import FilePath
except ImportError:
	from filepath import FilePath


ADS_NAME = u"_M"
VERSION = "\x07"


def getUnixTime(t):
	# 89 = number of leap year days between 1601 and 1970
	# http://src.chromium.org/svn/trunk/src/base/time_win.cc
	offset = ((1970-1601)*365+89)*24*60*60*1000*1000*10
	x = t - offset
	return x / float(1000*1000*10)


class StaticBody(tuple):
	__slots__ = ()
	_MARKER = object()

	timeMarked = property(operator.itemgetter(1))
	mtime = property(operator.itemgetter(2))
	checksums = property(operator.itemgetter(3))

	def __new__(cls, timeMarked, mtime, checksums):
		return tuple.__new__(cls, (cls._MARKER, timeMarked, mtime, checksums))


	def __repr__(self):
		return '%s(%r, %r, %r)' % (self.__class__.__name__, self[1], self[2], self[3])


	def getDescription(self):
		markedStr = datetime.datetime.utcfromtimestamp(self.timeMarked).isoformat()
		mtimeStr = datetime.datetime.utcfromtimestamp(getUnixTime(self.mtime))
		checksumsHex = list(s.encode("hex") for s in self.checksums)
		return "<StaticBody marked at %s when mtime was %s; checksums=%r>" % (
			markedStr, mtimeStr, checksumsHex)


	def encode(self):
		return (
			VERSION +
			"\x00" +
			struct.pack("<d", self.timeMarked) +
			struct.pack("<Q", self.mtime) +
			"".join(self.checksums))



class VolatileBody(tuple):
	__slots__ = ()
	_MARKER = object()

	timeMarked = property(operator.itemgetter(1))

	def __new__(cls, timeMarked):
		return tuple.__new__(cls, (cls._MARKER, timeMarked))


	def __repr__(self):
		return '%s(%r)' % (self.__class__.__name__, self[1])


	def getDescription(self):
		markedStr = datetime.datetime.utcfromtimestamp(self.timeMarked).isoformat()
		return "<VolatileBody marked at %s>" % (markedStr,)


	def encode(self):
		return VERSION + "\x01" + struct.pack("<d", self.timeMarked)



UNC_PREFIX = u"\\\\?\\"

def absPathToUncPath(p):
	r"""
	See http://msdn.microsoft.com/en-us/library/aa365247%28v=vs.85%29.aspx#maxpath
	"""
	return UNC_PREFIX + p


def upgradeFilepath(f):
	r"""
	@param f: a L{FilePath} to upgrade.
	@return: a possibly-upgraded L{FilePath}.
	"""
	if not f.path.startswith(UNC_PREFIX):
		return FilePath(absPathToUncPath(f.path))
	return f


def getADSPath(f):
	return FilePath(f.path + u":" + ADS_NAME)


class UnreadableOldVersion(Exception):
	pass



def decodeBody(fh):
	fh.seek(0)
	version = ord(fh.read(1))
	if version < 7:
		raise UnreadableOldVersion("Can't read version %r" % (version,))
	isVolatile = bool(ord(fh.read(1)))
	timeMarked = struct.unpack("<d", fh.read(8))[0]
	mtime = struct.unpack("<Q", fh.read(8))[0]
	if not isVolatile:
		checksums = []
		while True:
			c = fh.read(8)
			assert len(c) in (0, 8), "Got %d bytes instead of expected 0 or 8: %r" % (len(c), c)
			if not c:
				break
			checksums.append(c)
		return StaticBody(timeMarked, mtime, checksums)
	else:
		return VolatileBody(timeMarked)


def _getChecksums(fh, readSize, blockSize):
	"""
	Yields an 8-byte hash for every `blockSize` bytes in `fh`.
	Doesn't yield anything for an empty file.  Yields one hash for
	a `blockSize`-sized file.
	"""
	if blockSize % readSize != 0:
		raise ValueError("blockSize must be divisible by readSize; "
			"arguments were readSize=%r, blockSize=%r)" % (readSize, blockSize))

	fh.seek(0)
	m = hashlib.md5()
	while True:
		data = fh.read(readSize)
		if not data:
			break
		m.update(data)
		if len(data) < readSize:
			yield m.digest()[:8]
			break
		elif fh.tell() % blockSize == 0:
			yield m.digest()[:8]
			m = hashlib.md5()


def getChecksums(fh):
	return list(_getChecksums(fh, readSize=1*1024*1024, blockSize=32*1024*1024))


class GetTimestampFailed(Exception):
	pass



class SetTimestampFailed(Exception):
	pass



FILE_SHARE_ALL = (
	win32file.FILE_SHARE_DELETE |
	win32file.FILE_SHARE_READ |
	win32file.FILE_SHARE_WRITE)

def getPreciseModificationTime(fname):
	"""
	GetFileTime:
	http://msdn.microsoft.com/en-us/library/ms724320%28v=vs.85%29.aspx
	"""
	if not isinstance(fname, unicode):
		raise TypeError("Filename %r must be unicode, was %r" % (fname, type(fname),))

	mtime = ctypes.c_ulonglong(0)
	h = ctypes.windll.kernel32.CreateFileW(
		fname, win32file.GENERIC_READ, FILE_SHARE_ALL, 0,
		win32file.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, 0)
	if h == win32file.INVALID_HANDLE_VALUE:
		raise GetTimestampFailed("Couldn't open file %r" % (fname,))
	try:
		ret = ctypes.windll.kernel32.GetFileTime(h, 0, 0, ctypes.pointer(mtime))
		if ret == 0:
			raise GetTimestampFailed(
				"Return code 0 from GetFileTime: %r" % (ctypes.GetLastError(),))
	finally:
		ctypes.windll.kernel32.CloseHandle(h)
	return mtime.value


def setPreciseModificationTime(fname, mtime):
	"""
	SetFileTime:
	http://msdn.microsoft.com/en-us/library/ms724933%28v=vs.85%29.aspx
	"""
	if not isinstance(fname, unicode):
		raise TypeError("Filename %r must be unicode, was %r" % (fname, type(fname),))

	mtime = ctypes.c_ulonglong(mtime)
	h = ctypes.windll.kernel32.CreateFileW(
		fname, win32file.GENERIC_WRITE, FILE_SHARE_ALL, 0,
		win32file.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, 0)
	if h == win32file.INVALID_HANDLE_VALUE:
		raise SetTimestampFailed("Couldn't open file %r" % (fname,))
	try:
		ret = ctypes.windll.kernel32.SetFileTime(h, 0, 0, ctypes.pointer(mtime))
		if ret == 0:
			raise SetTimestampFailed(
				"Return code 0 from SetFileTime: %r" % (ctypes.GetLastError(),))
	finally:
		ctypes.windll.kernel32.CloseHandle(h)


def setChecksums(f, verbose):
	timeMarked = time.time()

	try:
		fh = open(f.path, "rb")
	except IOError:
		writeToBothIfVerbose("NOREAD\t%r" % (f.path,), verbose)
		return
	try:
		checksums = getChecksums(fh)
	finally:
		fh.close()
	mtime = getPreciseModificationTime(f.path)
	sb = StaticBody(timeMarked, mtime, checksums)

	mode = os.stat(f.path).st_mode
	wasReadOnly = not mode & stat.S_IWRITE
	try:
		if wasReadOnly:
			# Unset the read-only flag
			os.chmod(f.path, stat.S_IWRITE)
		with open(getADSPath(f).path, "wb") as adsW:
			adsW.write(sb.encode())
	finally:
		# Set the mtime back to what it was before the ADS was written.
		# We set the mtime on the ADS instead of the file because it
		# might be impossible to open the file with GENERIC_WRITE access
		# if some program has the file open.  Note that timestamps are
		# per-file, not per-stream.
		#
		# Note that if this program is killed during the write() above,
		# the mtime and read-only flags may remain incorrect.
		setPreciseModificationTime(getADSPath(f).path, mtime)
		# TODO: perhaps print something other than "NOWRITE" if the
		# above fails.
		if wasReadOnly:
			os.chmod(f.path, stat.S_IREAD)


def writeToBothIfVerbose(msg, verbose):
	sys.stdout.write(msg + "\n")
	sys.stdout.flush()
	if verbose:
		sys.stderr.write(msg + "\n")
		sys.stderr.flush()


def writeToStdout(msg):
	sys.stdout.write(msg + "\n")
	sys.stdout.flush()


def writeToStderr(msg):
	sys.stderr.write(msg + "\n")
	sys.stderr.flush()


def setChecksumsOrPrintMessage(f, verbose):
	try:
		setChecksums(f, verbose)
	except GetTimestampFailed:
		writeToBothIfVerbose("NOREAD\t%r" % (f.path,), verbose)
	except SetTimestampFailed:
		writeToBothIfVerbose("NOWRITE\t%r" % (f.path,), verbose)


def getBody(f):
	try:
		with open(getADSPath(f).path, "rb") as adsR:
			try:
				body = decodeBody(adsR)
			except UnreadableOldVersion:
				body = None
	except IOError:
		body = None
	return body


# Four possibilities here:
# verify=False, write=False -> just recurse and print NEW/NOREAD/MODIFIED
# verify=True, write=False -> verify checksums for non-modified files
# verify=True, write=True -> verify and write new checksums where needed
# verify=False, write=True -> ignore existing checksums, write new checksums where needed

def verifyOrSetChecksums(f, verify, write, inspect, verbose):
	body = getBody(f)
	if inspect:
		writeToStdout("INSPECT\t%r" % (f.path,))
		writeToStdout("#\t%s" % (body.getDescription() if body else repr(body),))
	if body is None:
		if verbose:
			writeToStderr("NEW\t%r" % (f.path,))
		if write:
			setChecksumsOrPrintMessage(f, verbose)
	else:
		if isinstance(body, StaticBody):
			try:
				mtime = getPreciseModificationTime(f.path)
			except GetTimestampFailed:
				writeToBothIfVerbose("NOREAD\t%r" % (f.path,), verbose)
			##print repr(body.mtime), repr(mtime)
			if body.mtime != mtime:
				writeToBothIfVerbose("MODIFIED\t%r" % (f.path,), verbose)
				if write:
					# Existing checksums are probably obsolete, so just
					# set new checksums.
					setChecksumsOrPrintMessage(f, verbose)
			else:
				if verify:
					with open(f.path, "rb") as fh:
						checksums = getChecksums(fh)
					if checksums != body.checksums:
						writeToBothIfVerbose("CORRUPT\t%r" % (f.path,), verbose)
					else:
						if verbose:
							writeToStderr("VERIFIED\t%r" % (f.path,))


def isReparsePoint(fname):
	if not isinstance(fname, unicode):
		raise TypeError("Filename %r must be unicode, was %r" % (fname, type(fname),))

	attribs = win32file.GetFileAttributesW(fname)
	return bool(attribs & winnt.FILE_ATTRIBUTE_REPARSE_POINT)


def shouldDescend(f):
	# http://twistedmatrix.com/trac/ticket/5123
	if not f.isdir():
		return False
	# Don't descend any reparse points (symlinks are reparse points too).
	if isReparsePoint(f.path):
		return False
	try:
		os.listdir(f.path)
	except OSError: # A "Permission denied" WindowsError, usually
		writeToBothOuts("NOLISTDIR\t%r" % (f.path,))
		return False
	return True


def main():
	parser = argparse.ArgumentParser(description="""
	Reads and/or writes checksums of files in the files' ADS (alternate data stream).
	Works only on NTFS partitions.

	--verify, --write, and --inspect can be combined.  If none of these are
	specified, files will be checked only for lack of checksum data or updated mtime.
	""")

	parser.add_argument('path', metavar='PATH', type=str, nargs='+',
		help="a file or directory")
	parser.add_argument('-v', '--verify', dest='verify', action='store_true',
		help="verify already-stored checksums to detect file corruption")
	parser.add_argument('-w', '--write', dest='write', action='store_true',
		help="calculate and write checksums for files that "
			"have no checksum, or have an updated mtime")
	parser.add_argument('-i', '--inspect', dest='inspect', action='store_true',
		help="print information about existing checksum data")
	parser.add_argument('-q', '--quiet', dest='verbose', action='store_false',
		default=True, help="don't print important and unimportant messages to stderr")

	args = parser.parse_args()

	for fname in args.path:
		# *must* use a unicode path because listdir'ing a `str` extended path
		# raises WindowsError.
		p = upgradeFilepath(FilePath(fname.decode("ascii")))
		if p.isdir():
			for f in p.walk(descend=shouldDescend):
				if f.isfile() and not isReparsePoint(f.path):
					verifyOrSetChecksums(f, verify=args.verify, write=args.write,
						inspect=args.inspect, verbose=args.verbose)
		else:
			f = p
			if f.isfile() and not isReparsePoint(f.path):
				verifyOrSetChecksums(f, verify=args.verify, write=args.write,
					inspect=args.inspect, verbose=args.verbose)


if __name__ == '__main__':
	main()
