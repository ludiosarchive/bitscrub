import os
import sys

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


try:
	from refbinder.api import bindRecursive, enableBinders
except ImportError:
	pass
else:
	enableBinders()
	bindRecursive(sys.modules[__name__], _postImportVars)
