from __future__ import with_statement

import sys
import struct
import time
import zlib
import operator
from collections import namedtuple

try:
	from twisted.python.filepath import FilePath
except ImportError:
	from filepath import FilePath


ADS_NAME = u"_M"
VERSION = "\x02"


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
			struct.pack("d", self.timeMarked) +
			struct.pack("d", self.mtime) +
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
		return VERSION + "\x01" + struct.pack("d", self.timeMarked)



UNC_PREFIX = "\\\\?\\"

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
	timeMarked = struct.unpack("d", fh.read(8))[0]
	if version >= 2:
		mtime = struct.unpack("d", fh.read(8))[0]
	else:
		mtime = None
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


def setChecksums(f):
	timeMarked = time.time()

	with open(f.path, "rb") as fh:
		checksums = getChecksums(fh)
	mtime = f.getModificationTime()
	sb = StaticBody(timeMarked, mtime, checksums)
	# Note: can't use setContent to write an ADS
	with open(getADSPath(f).path, "wb") as adsW:
		adsW.write(sb.encode())


def verifyOrSetChecksums(f):
	try:
		with open(getADSPath(f).path, "rb") as adsR:
			body = decodeBody(adsR)
	except IOError:
		body = None

	if body is None:
		print "NEW\t%r" % (f.path,)
		setChecksums(f)
	else:
		if isinstance(body, StaticBody):
			mtime = f.getModificationTime()
			print body.mtime, mtime
			if body.mtime != mtime:
				print "MODIFIED\t%r" % (f.path,)
				# Existing checksums are probably obsolete, so just
				# set new checksums.
				setChecksums(f)
			else:
				with open(f.path, "rb") as fh:
					checksums = getChecksums(fh)
				if checksums != body.checksums:
					print "CORRUPT\t%r" % (f.path,)


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


if __name__ == '__main__':
	main()
