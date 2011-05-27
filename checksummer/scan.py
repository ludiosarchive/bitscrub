import sys
import struct
import time
import zlib
try:
	from cStringIO import StringIO
except ImportError:
	from StringIO import StringIO

try:
	from twisted.python.filepath import FilePath
except ImportError:
	from filepath import FilePath


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


ADS_NAME = u"_M"
VERSION = "\x00"

def getADSPath(f):
	return FilePath(f.path + u":" + ADS_NAME)


def encodeBody(timeChecked, checksums):
	buf = StringIO()
	buf.write(VERSION)
	buf.write(struct.pack("d", timeChecked))
	for c in checksums:
		buf.write(struct.pack("i", c))
	return buf.getvalue()


def decodeBody(f):
	f.seek(0)
	version = f.read(1)
	timeChecked = struct.unpack("d", f.read(4))[0]
	checksums = []
	while True:
		c = f.read(4)
		assert len(c) in (0, 4), "Got %d bytes instead of expected 0 or 4: %r" % (len(c), c)
		if not c:
			break
		checksums.append(struct.unpack("i", c)[0])
	return version, timeChecked, checksums


def main():
	# *must* use a unicode path because listdir'ing a `str` extended path
	# raises WindowsError.
	root = upgradeFilepath(FilePath(sys.argv[1].decode("ascii")))
	for p in root.walk():
		try:
			hashes = getADSPath(p).getContent()
		except IOError:
			hashes = None


if __name__ == '__main__':
	main()
