import sys
import struct
import datetime
import ctypes
import win32file
import winnt
from winioctlcon import FSCTL_SET_COMPRESSION

COMPRESSION_FORMAT_NONE = struct.pack('H', 0)
COMPRESSION_FORMAT_DEFAULT = struct.pack('H', 1)

try:
	from twisted.python.filepath import FilePath
except ImportError:
	from filepath import FilePath

_postImportVars = vars().keys()


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


class OpenFailed(Exception):
	pass



FILE_SHARE_ALL = (
	win32file.FILE_SHARE_DELETE |
	win32file.FILE_SHARE_READ |
	win32file.FILE_SHARE_WRITE)

def open(fname, reading, writing, shareMode=FILE_SHARE_ALL,
creationDisposition=win32file.OPEN_EXISTING):
	"""
	Open a file for reading or writing.  By default, file must already exist.
	By default, all sharing modes are allowed, unlike the Python open(),
	which prohibits file deletion.
	"""
	if not isinstance(fname, unicode):
		raise TypeError("Filename %r must be unicode, was %r" % (fname, type(fname),))

	if not (reading or writing):
		raise ValueError("You must open the file for reading, writing, or both.")
	desiredAccess = 0
	if reading:
		desiredAccess |= win32file.GENERIC_READ
	if writing:
		desiredAccess |= win32file.GENERIC_WRITE

	h = ctypes.windll.kernel32.CreateFileW(
		fname, desiredAccess, shareMode, 0,
		creationDisposition, win32file.FILE_ATTRIBUTE_NORMAL, 0)
	if h == win32file.INVALID_HANDLE_VALUE:
		raise OpenFailed("Couldn't open file %r" % (fname,))
	return h


def close(h):
	ctypes.windll.kernel32.CloseHandle(h)


class ReadFailed(Exception):
	pass



_lastReadBuffer = [-1, None]

def read(h, length):
	# If the length is the same or less, use the last buffer.
	# It doesn't matter that it already contains data.
	if length <= _lastReadBuffer[0]:
		sbuf = _lastReadBuffer[1]
	else:
		sbuf = ctypes.create_string_buffer(length)
		_lastReadBuffer[:] = [length, sbuf]

	bytesRead = ctypes.c_long(0)
	ret = ctypes.windll.kernel32.ReadFile(
		ctypes.c_long(h),
		ctypes.byref(sbuf),
		ctypes.c_long(length),
		ctypes.byref(bytesRead),
		ctypes.c_long(0))

	if not ret:
		raise ReadFailed("Couldn't read from handle %r (%d bytes)" % (h, length))

	return sbuf.raw[:bytesRead.value]


class GetLengthFailed(Exception):
	pass



def getFileSize(h):
	length = ctypes.c_long(0)
	ret = ctypes.windll.kernel32.GetFileSizeEx(
		ctypes.c_long(h),
		ctypes.byref(length))

	if not ret:
		raise ReadFailed("Couldn't get length of handle %r" % (h,))

	return length.value


class WriteFailed(Exception):
	pass



def write(h, bytes):
	sbuf = ctypes.create_string_buffer(bytes)
	bytesWritten = ctypes.c_long(len(bytes))
	ret = ctypes.windll.kernel32.WriteFile(
		ctypes.c_long(h),
		ctypes.byref(sbuf),
		ctypes.c_long(len(bytes)), # number of bytes to write
		ctypes.byref(bytesWritten),
		ctypes.c_long(0))

	if not ret:
		raise WriteFailed("Couldn't write to handle %r (%d bytes)" % (h, len(bytes)))

	if bytesWritten.value != len(bytes):
		raise WriteFailed("WriteFile wrote %d bytes instead of all %d "
			"bytes to handle %r" % (bytesWritten.value, len(bytes), len(bytes)))



class SeekFailed(Exception):
	pass


def seek(h, pos, whence=0):
	try:
		ret = ctypes.windll.kernel32.SetFilePointerEx(
			ctypes.c_long(h),
			ctypes.c_longlong(pos),
			ctypes.c_long(0), # NULL for lpNewFilePointer
			ctypes.c_long(whence)
		)
	except WindowsError as e:
		raise SeekFailed("%r" % (e,))

	if not ret:
		raise SeekFailed("Couldn't seek handle %r to %d (whence=%r)" % (h, pos, whence))


def compress(h):
	"""
	NTFS-compress file at handle C{h}.  C{h} must be opened for reading and writing.
	"""
	win32file.DeviceIoControl(h, FSCTL_SET_COMPRESSION, COMPRESSION_FORMAT_DEFAULT, 0)


def decompress(h):
	"""
	NTFS-decompress file at handle C{h}.  C{h} must be opened for reading and writing.
	"""
	win32file.DeviceIoControl(h, FSCTL_SET_COMPRESSION, COMPRESSION_FORMAT_NONE, 0)


def isCompressed(fname):
	if not isinstance(fname, unicode):
		raise TypeError("Filename %r must be unicode, was %r" % (fname, type(fname),))

	attribs = win32file.GetFileAttributesW(fname)
	return bool(attribs & winnt.FILE_ATTRIBUTE_COMPRESSED)


class GetMetadataFailed(Exception):
	pass



class SetMetadataFailed(Exception):
	pass



def winTimeToDatetime(t):
	return (datetime.datetime(1601, 1, 1) +
		datetime.timedelta(microseconds=t / 10))


def getCreationTimeNanoseconds(h):
	ctime, _, _ = getCreationAccessModificationTimeNanoseconds(h)
	return ctime


def getAccessTimeNanoseconds(h):
	_, atime, _ = getCreationAccessModificationTimeNanoseconds(h)
	return atime


def getModificationTimeNanoseconds(h):
	_, _, mtime = getCreationAccessModificationTimeNanoseconds(h)
	return mtime


def setCreationTimeNanoseconds(h, ns):
	return setCreationAccessModificationTimeNanoseconds(h, ns, 0, 0)


def setAccessTimeNanoseconds(h, ns):
	return setCreationAccessModificationTimeNanoseconds(h, 0, ns, 0)


def setModificationTimeNanoseconds(h, ns):
	return setCreationAccessModificationTimeNanoseconds(h, 0, 0, ns)


def getCreationAccessModificationTimeNanoseconds(h):
	ctime = ctypes.c_ulonglong(0)
	atime = ctypes.c_ulonglong(0)
	mtime = ctypes.c_ulonglong(0)
	ret = ctypes.windll.kernel32.GetFileTime(
		h, ctypes.pointer(ctime), ctypes.pointer(atime), ctypes.pointer(mtime))
	if ret == 0:
		raise GetMetadataFailed(
			"Return code 0 from GetFileTime: %r" % (ctypes.GetLastError(),))
	return (ctime.value, atime.value, mtime.value)


def setCreationAccessModificationTimeNanoseconds(h, c_ns, a_ns, m_ns):
	ctime = ctypes.c_ulonglong(c_ns)
	atime = ctypes.c_ulonglong(a_ns)
	mtime = ctypes.c_ulonglong(m_ns)
	ret = ctypes.windll.kernel32.SetFileTime(
		h, ctypes.pointer(ctime), ctypes.pointer(atime), ctypes.pointer(mtime))
	if ret == 0:
		raise SetMetadataFailed(
			"Return code 0 from SetFileTime: %r" % (ctypes.GetLastError(),))


def isReparsePoint(fname):
	if not isinstance(fname, unicode):
		raise TypeError("Filename %r must be unicode, was %r" % (fname, type(fname),))

	attribs = win32file.GetFileAttributesW(fname)
	return bool(attribs & winnt.FILE_ATTRIBUTE_REPARSE_POINT)


def isDrive(f):
	return f.path.endswith(u":\\")


def parentEx(f):
	"""
	A version of FilePath.parent that works correctly with extended paths.
	"""
	if isDrive(f):
		return f
	parent = f.parent()
	# f.parent() of \\?\C:\dir is \\?\C: , so fix it:
	if parent.path.endswith(u":"):
		return FilePath(parent.path + u"\\")
	return parent


try:
	from refbinder.api import bindRecursive, enableBinders
except ImportError:
	pass
else:
	enableBinders()
	bindRecursive(sys.modules[__name__], _postImportVars)
