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
VERSION = "\x01"


class StaticBody(tuple):
	__slots__ = ()
	_MARKER = object()

	timeMarked = property(operator.itemgetter(1))
	checksums = property(operator.itemgetter(2))

	def __new__(cls, timeMarked, checksums):
		return tuple.__new__(cls, (cls._MARKER, timeMarked, checksums))


	def __repr__(self):
		return '%s(%r, %r)' % (self.__class__.__name__, self[1], self[2])


	def encode(self):
		return VERSION + "\x00" + struct.pack("d", self.timeMarked) + "".join(self.checksums)



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
	version = fh.read(1)
	isVolatile = bool(ord(fh.read(1)))
	timeMarked = struct.unpack("d", fh.read(4))[0]
	if not isVolatile:
		checksums = []
		while True:
			c = fh.read(4)
			assert len(c) in (0, 4), "Got %d bytes instead of expected 0 or 4: %r" % (len(c), c)
			if not c:
				break
			checksums.append(c)
		return StaticBody(timeMarked, checksums)
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


def verifyOrSetChecksums(f):
	adsPath = getADSPath(f)
	try:
		hashes = adsPath.getContent()
	except IOError:
		hashes = None

	if hashes is None:
		timeMarked = time.time()

		with open(f.path, "rb") as fh:
			checksums = getChecksums(fh)
		sb = StaticBody(timeMarked, checksums)
		print f, repr(len(sb.encode()))
		##adsPath.setContent(sb.encode())


def main():
	# *must* use a unicode path because listdir'ing a `str` extended path
	# raises WindowsError.
	root = upgradeFilepath(FilePath(sys.argv[1].decode("ascii")))
	for f in root.walk():
		if f.isfile():
			verifyOrSetChecksums(f)


if __name__ == '__main__':
	main()
