"""
Checksummer reads and/or writes checksums of files in the files' ADS
(alternate data stream).  Works only on NTFS partitions.


TODO:

*	Support passing in a "file exclude function"; function is called for every
	file; if return value is True, do scan the file.


Some useful documentation for developers:

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
import hashlib

import win32file

try:
	import simplejson as json
except ImportError:
	import json

try:
	from twisted.python.filepath import FilePath
except ImportError:
	from filepath import FilePath

import checksummer.winfile as winfile


ADS_NAME = u"_M"
VERSION = chr(8)


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
		mtimeDate = (datetime.datetime(1601, 1, 1) +
			datetime.timedelta(microseconds=self.mtime / 10))
		checksumsHex = list(s.encode("hex") for s in self.checksums)
		return "<StaticBody marked at %s when mtime was %s; checksums=%r>" % (
			markedStr, mtimeDate.isoformat(), checksumsHex)


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



def getADSPath(f):
	return FilePath(f.path + u":" + ADS_NAME)


class UnreadableOldVersion(Exception):
	pass



def decodeBody(h):
	winfile.seek(h, 0)
	version = ord(winfile.read(h, 1))
	if version < 7:
		raise UnreadableOldVersion("Can't read version %r" % (version,))
	if version == 7:
		# Version 7 had a bug that omitted a checksum for some files.
		if winfile.getFileSize(h) % (1024*1024) == 0:
			raise UnreadableOldVersion("Can't read version %r for files "
				"whose length is a multiple of 1024*1024" % (version,))
	volatileStr = winfile.read(h, 1)
	if not volatileStr:
		# TODO: new exception
		raise UnreadableOldVersion("Truncated ADS?")
	isVolatile = bool(ord(volatileStr))
	timeMarked = struct.unpack("<d", winfile.read(h, 8))[0]
	mtime = struct.unpack("<Q", winfile.read(h, 8))[0]
	if not isVolatile:
		checksums = []
		while True:
			c = winfile.read(h, 8)
			assert len(c) in (0, 8), "Got %d bytes instead of expected 0 or 8: %r" % (len(c), c)
			if not c:
				break
			checksums.append(c)
		return StaticBody(timeMarked, mtime, checksums)
	else:
		return VolatileBody(timeMarked)


def _getChecksums(h, readSize, blockSize):
	"""
	Yields an 8-byte hash for every `blockSize` bytes in `h`.
	Doesn't yield anything for an empty file.  Yields one hash for
	a `blockSize`-sized file.
	"""
	if blockSize % readSize != 0:
		raise ValueError("blockSize must be divisible by readSize; "
			"arguments were readSize=%r, blockSize=%r)" % (readSize, blockSize))

	winfile.seek(h, 0)
	pos = 0
	m = hashlib.md5()
	blockInProgress = False
	while True:
		data = winfile.read(h, readSize)
		pos += len(data)
		if not data:
			if blockInProgress:
				yield m.digest()[:8]
			break
		m.update(data)
		if len(data) < readSize:
			yield m.digest()[:8]
			break
		elif pos % blockSize == 0:
			yield m.digest()[:8]
			m = hashlib.md5()
			blockInProgress = False
		else:
			blockInProgress = True


def getChecksums(h):
	return list(_getChecksums(h, readSize=32*1024, blockSize=32*1024*1024))


def setChecksums(f, verbose):
	timeMarked = time.time()

	try:
		h = winfile.open(f.path, reading=True, writing=False)
	except winfile.OpenFailed:
		writeToBothIfVerbose("NOREAD\t%r" % (f.path,), verbose)
		return
	try:
		checksums = getChecksums(h)
		mtime = winfile.getModificationTimeNanoseconds(h)
	finally:
		winfile.close(h)
	sb = StaticBody(timeMarked, mtime, checksums)

	mode = os.stat(f.path).st_mode
	wasReadOnly = not mode & stat.S_IWRITE
	if wasReadOnly:
		# Unset the read-only flag
		os.chmod(f.path, stat.S_IWRITE)
	adsH = winfile.open(getADSPath(f).path, reading=False, writing=True,
		creationDisposition=win32file.OPEN_ALWAYS)
	try:
		winfile.write(adsH, sb.encode())
	finally:
		# Set the mtime back to what it was before the ADS was written.
		# We set the mtime on the ADS instead of the file because it
		# might be impossible to open the file with GENERIC_WRITE access
		# if some program has the file open.  Note that timestamps are
		# per-file, not per-stream.
		#
		# Note that if this program is killed during the write() above,
		# the mtime and read-only flags may remain incorrect.
		winfile.setModificationTimeNanoseconds(adsH, mtime)
		if wasReadOnly:
			os.chmod(f.path, stat.S_IREAD)
		winfile.close(adsH)


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
	except winfile.OpenFailed:
		writeToBothIfVerbose("NOREAD\t%r" % (f.path,), verbose)
	except winfile.WriteFailed:
		writeToBothIfVerbose("NOWRITE\t%r" % (f.path,), verbose)


# Four possibilities here:
# verify=False, write=False -> just recurse and print NEW/NOREAD/MODIFIED
# verify=True, write=False -> verify checksums for non-modified files
# verify=True, write=True -> verify and write new checksums where needed
# verify=False, write=True -> ignore existing checksums, write new checksums where needed

def verifyOrSetChecksums(f, verify, write, inspect, verbose):
	body = None
	try:
		adsR = winfile.open(getADSPath(f).path, reading=True, writing=False)
	except winfile.OpenFailed:
		pass
	else:
		try:
			body = decodeBody(adsR)
			mtime = winfile.getModificationTimeNanoseconds(adsR)
		except UnreadableOldVersion:
			body = None
		finally:
			winfile.close(adsR)

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
			##print repr(body.mtime), repr(mtime)
			if body.mtime != mtime:
				writeToBothIfVerbose("MODIFIED\t%r" % (f.path,), verbose)
				if write:
					# Existing checksums are probably obsolete, so just
					# set new checksums.
					setChecksumsOrPrintMessage(f, verbose)
			else:
				if verify:
					h = winfile.open(f.path, reading=True, writing=False)
					try:
						checksums = getChecksums(h)
					finally:
						winfile.close(h)
					if checksums != body.checksums:
						writeToBothIfVerbose("CORRUPT\t%r" % (f.path,), verbose)
					else:
						if verbose:
							writeToStderr("VERIFIED\t%r" % (f.path,))


def shouldDescend(f):
	# http://twistedmatrix.com/trac/ticket/5123
	if not f.isdir():
		return False
	excludes = getExcludesForDirectory(winfile.parentEx(f))
	if f.basename() in excludes:
		return False
	# Don't descend any reparse points (symlinks are reparse points too).
	if winfile.isReparsePoint(f.path):
		return False
	try:
		os.listdir(f.path)
	except OSError: # A "Permission denied" WindowsError, usually
		writeToBothOuts("NOLISTDIR\t%r" % (f.path,))
		return False
	return True


def handlePath(f, verify, write, inspect, verbose):
	if f.isfile() and not winfile.isReparsePoint(f.path):
		verifyOrSetChecksums(f, verify, write, inspect, verbose)


def getContentIfExists(f, maxRead):
	try:
		h = winfile.open(f.path, reading=True, writing=False)
	except winfile.OpenFailed:
		return None
	try:
		return winfile.read(h, maxRead)
		# Above might raise exception if .read() fails for some reason
	finally:
		winfile.close(h)


_lastExcludes = [None, None]

def getExcludesForDirectory(p):
	if p == _lastExcludes[0]:
		return _lastExcludes[1]

	bytes = getContentIfExists(p.child(".checksummer.json"), 2**16)
	if bytes is None:
		config = {}
	else:
		config = json.loads(bytes)
		# Above might raise exception if JSON is invalid
	excludes = set(config.get("excludes", []))

	_lastExcludes[:] = [p, excludes]

	return excludes


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
	kwargs = dict(verify=args.verify, write=args.write,
		inspect=args.inspect, verbose=args.verbose)

	for fname in args.path:
		# *must* use a unicode path because listdir'ing a `str` extended path
		# raises WindowsError.
		p = winfile.upgradeFilepath(FilePath(fname.decode("ascii")))
		if p.isdir():
			for f in p.walk(descend=shouldDescend):
				excludes = getExcludesForDirectory(winfile.parentEx(f))
				if f.basename() not in excludes:
					handlePath(f, **kwargs)
		else:
			f = p
			excludes = getExcludesForDirectory(winfile.parentEx(f))
			if f.basename() not in excludes:
				handlePath(f, **kwargs)


if __name__ == '__main__':
	main()
