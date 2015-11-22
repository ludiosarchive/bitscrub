import os
import sys
import xattr
import struct

try:
	from twisted.python.filepath import FilePath
except ImportError:
	from filepath import FilePath

_postImportVars = vars().keys()


def upgradeFilepath(f):
	return f


OpenFailed = (OSError, IOError)


pyOpen = open

def open(fname, reading, writing, shareMode=None, creationDisposition=None):
	# writing=, shareMode=, creationDisposition are ignored
	return pyOpen(fname, "rb")


def close(h):
	h.close()


ReadFailed = (OSError, IOError)

def read(h, length):
	return h.read(length)


GetLengthFailed = (OSError, IOError)

def getFileSize(h):
	h.seek(0, 2)
	return h.tell()


WriteFailed = (OSError, IOError)

def write(h, bytes):
	h.write(bytes)


SeekFailed = (OSError, IOError)

def seek(h, pos, whence=0):
	return h.seek(pos, whence)


def isReparsePoint(f):
	return os.path.islink(f.path)


def parentEx(f):
	return f.parent()


def getCreationAccessModificationTimeNanoseconds(h):
	# http://www.tuxera.com/community/ntfs-3g-advanced/extended-attributes/
	crtime, mtime, atime, ctime = struct.unpack('<QQQQ', xattr.getxattr(h, 'system.ntfs_times'))
	return (crtime, atime, mtime)


def getCreationTimeNanoseconds(h):
	ctime, _, _ = getCreationAccessModificationTimeNanoseconds(h)
	return ctime


def getAccessTimeNanoseconds(h):
	_, atime, _ = getCreationAccessModificationTimeNanoseconds(h)
	return atime


def getModificationTimeNanoseconds(h):
	_, _, mtime = getCreationAccessModificationTimeNanoseconds(h)
	return mtime


try:
	from refbinder.api import bindRecursive, enableBinders
except ImportError:
	pass
else:
	enableBinders()
	bindRecursive(sys.modules[__name__], _postImportVars)
