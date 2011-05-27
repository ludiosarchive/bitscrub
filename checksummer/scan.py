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
import zlib
import operator
import win32file
import ctypes
import hashlib
from collections import namedtuple

try:
	from twisted.python.filepath import FilePath
except ImportError:
	from filepath import FilePath


ADS_NAME = u"_M"
VERSION = "\x04"


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


	def getChecksumsDigest(self):
		return hashlib.sha1("".join(self.checksums)).digest()


	def encode(self):
		joinedChecksums = "".join(self.checksums)
		checksumsDigest = hashlib.sha1(joinedChecksums).digest()
		return (
			VERSION +
			"\x00" +
			struct.pack("<d", self.timeMarked) +
			struct.pack("<Q", self.mtime) +
			checksumsDigest +
			joinedChecksums)



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


def decodeBody(fh):
	fh.seek(0)
	version = ord(fh.read(1))
	isVolatile = bool(ord(fh.read(1)))
	timeMarked = struct.unpack("<d", fh.read(8))[0]
	if version >= 2:
		mtime = struct.unpack("<Q", fh.read(8))[0]
	else:
		mtime = None
	if version >= 4:
		checksumsDigest = fh.read(160/8)
	else:
		checksumsDigest = "\x00" * (160/8)
	# Note: checksumsDigest isn't validated anywhere yet
	if not isVolatile:
		checksums = []
		while True:
			c = fh.read(4)
			assert len(c) in (0, 4), "Got %d bytes instead of expected 0 or 4: %r" % (len(c), c)
			if not c:
				break
			checksums.append(c)
		return StaticBody(timeMarked, mtime, checksums)
	else:
		return VolatileBody(timeMarked)


def crc32Bytes(s):
	return struct.pack("i", zlib.crc32(s))


def getChecksums(fh):
	checksums = []

	fh.seek(0)
	while True:
		# Checksum every 4KB block, regardless of underlying filesystem
		# block size.
		bytes = fh.read(4096)
		if not bytes:
			break
		checksums.append(crc32Bytes(bytes))

	return checksums	


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
	sys.stderr.write(msg + "\n")


def writeToStderr(msg):
	sys.stderr.write(msg + "\n")


def setChecksumsOrPrintMessage(f):
	try:
		setChecksums(f)
	except GetTimestampFailed:
		writeToBothOuts("NOREAD\t%r" % (f.path,))
	except SetTimestampFailed:
		writeToBothOuts("NOWRITE\t%r" % (f.path,))


def verifyOrSetChecksums(f):
	try:
		with open(getADSPath(f).path, "rb") as adsR:
			body = decodeBody(adsR)
	except IOError:
		body = None

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


def main():
	command = sys.argv[1]
	# check files and update ADS for files with no ADS
	if command == "check":
		rootsBytes = sys.argv[2:]
		for rootBytes in rootsBytes:
			# *must* use a unicode path because listdir'ing a `str` extended path
			# raises WindowsError.
			root = upgradeFilepath(FilePath(rootBytes.decode("ascii")))
			for f in root.walk():
				if f.isfile():
					verifyOrSetChecksums(f)
	else:
		raise ValueError("Unknown command %r" % (command,))


if __name__ == '__main__':
	main()
