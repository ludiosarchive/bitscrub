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
import operator
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


def setChecksums(f):
	timeMarked = time.time()

	with open(f.path, "rb") as fh:
		checksums = getChecksums(fh)
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
		# Note that if this program is killed during the write() above,
		# the mtime will fail to be set back to the original mtime.
		setPreciseModificationTime(f.path, mtime)
		if wasReadOnly:
			os.chmod(f.path, stat.S_IREAD)


def writeToBothOuts(msg):
	sys.stdout.write(msg + "\n")
	sys.stdout.flush()
	sys.stderr.write(msg + "\n")
	sys.stderr.flush()


def writeToStderr(msg):
	sys.stderr.write(msg + "\n")
	sys.stderr.flush()


def setChecksumsOrPrintMessage(f):
	try:
		setChecksums(f)
	except GetTimestampFailed:
		writeToBothOuts("NOREAD\t%r" % (f.path,))
	except SetTimestampFailed:
		writeToBothOuts("NOWRITE\t%r" % (f.path,))


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


def verifyOrSetChecksums(f):
	body = getBody(f)
	if body is None:
		writeToStderr("NEW\t%r" % (f.path,))
		setChecksumsOrPrintMessage(f)
	else:
		if isinstance(body, StaticBody):
			try:
				mtime = getPreciseModificationTime(f.path)
			except GetTimestampFailed:
				writeToBothOuts("NOREAD\t%r" % (f.path,))
			##print repr(body.mtime), repr(mtime)
			if body.mtime != mtime:
				writeToBothOuts("MODIFIED\t%r" % (f.path,))
				# Existing checksums are probably obsolete, so just
				# set new checksums.
				setChecksumsOrPrintMessage(f)
			else:
				with open(f.path, "rb") as fh:
					checksums = getChecksums(fh)
				if checksums != body.checksums:
					writeToBothOuts("CORRUPT\t%r" % (f.path,))
				else:
					writeToStderr("CHECKED\t%r" % (f.path,))


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
	command = sys.argv[1]
	# check files and update ADS for files with no ADS, as well as files with an updated mtime
	if command == "check+write":
		rootsBytes = sys.argv[2:]
		for rootBytes in rootsBytes:
			# *must* use a unicode path because listdir'ing a `str` extended path
			# raises WindowsError.
			root = upgradeFilepath(FilePath(rootBytes.decode("ascii")))
			for f in root.walk(descend=shouldDescend):
				if f.isfile() and not isReparsePoint(f.path):
					verifyOrSetChecksums(f)
	elif command == "inspect":
		fname = sys.argv[2]
		f = upgradeFilepath(FilePath(fname.decode("ascii")))
		body = getBody(f)
		print "body for %r:" % (f.path,)
		print repr(body)
	else:
		raise ValueError("Unknown command %r" % (command,))


if __name__ == '__main__':
	main()
