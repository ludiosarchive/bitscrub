#!/usr/bin/python

"""
Checksummer reads and/or writes checksums of files in the files' ADS
(alternate data stream).  Works only on NTFS partitions.


TODO:

*	Support passing in a "file exclude function"; function is called for every
	file; if return value is True, do scan the file.

*	Notice when the mtime changes while the file is being read, and do
	something different.


Implementation notes:

Why do we use checksummer.winfile instead of the normall open()?  Because
the normal open() doesn't enable FILE_SHARE_DELETE, so no one can
delete the file when it's open.  This could mess up other programs as we
scan almost all of the files on the disk.


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
import types
import stat
import sys
import struct
import time
import datetime
import functools
import operator
import argparse
import hashlib

try:
	import simplejson as json
except ImportError:
	import json

try:
	from twisted.python.filepath import FilePath
except ImportError:
	from filepath import FilePath

if os.name == 'nt':
	from checksummer import winfile
else:
	from checksummer import posixfile as winfile

_postImportVars = vars().keys()


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
		mtimeDate = winfile.winTimeToDatetime(self.mtime)
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



class ADSOnlyOnWindows(Exception):
	pass



def getADSPath(f):
	if os.name != 'nt':
		raise ADSOnlyOnWindows()
	return FilePath(f.path + u":" + ADS_NAME)


class UnreadableBody(Exception):
	pass


def utf8IfUnicode(sOrU):
	if isinstance(sOrU, unicode):
		return sOrU.encode("utf-8")
	else:
		return sOrU


def decodeBody(h, fileSize):
	winfile.seek(h, 0)
	version_s = winfile.read(h, 1)
	if not version_s:
		raise UnreadableBody("Body is empty")
	version = ord(version_s)
	if version < 7:
		raise UnreadableBody("Can't read version %r" % (version,))
	if version == 7:
		# Version 7 had a bug that omitted a checksum for some files.
		if fileSize % (1024*1024) == 0:
			raise UnreadableBody("Can't read version %r for files "
				"whose length is a multiple of 1024*1024" % (version,))
	volatileStr = winfile.read(h, 1)
	if not volatileStr:
		raise UnreadableBody("Truncated ADS?")
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
	if os.name != 'nt':
		# LOL, go use ZFS
		raise RuntimeError("Can't set checksums on non-Windows")

	timeMarked = time.time()

	try:
		h = winfile.open(f.path, reading=True, writing=False)
	except winfile.OpenFailed:
		writeToBothIfVerbose("NOOPEN\t%r" % (f.path,), verbose)
		return None
	try:
		checksums = getChecksums(h)
		mtime = winfile.getModificationTimeNanoseconds(h)
	except winfile.ReadFailed:
		writeToBothIfVerbose("NOREAD\t%r" % (f.path,), verbose)
		return None
	except winfile.SeekFailed:
		writeToBothIfVerbose("NOSEEK\t%r" % (f.path,), verbose)
		return None
	finally:
		winfile.close(h)
	sb = StaticBody(timeMarked, mtime, checksums)

	mode = os.stat(f.path).st_mode
	wasReadOnly = not mode & stat.S_IWRITE
	if wasReadOnly:
		# Unset the read-only flag
		try:
			os.chmod(f.path, stat.S_IWRITE)
		except WindowsError:
			writeToBothIfVerbose("NOCHMOD\t%r" % (f.path,), verbose)
			return checksums
	adsH = winfile.open(getADSPath(f).path, reading=False, writing=True,
		creationDisposition=winfile.CREATE_ALWAYS)
	try:
		winfile.write(adsH, sb.encode())
	finally:
		# Get the handle again because in some cases (when the file is open
		# in uTorrent?), the handle disappears and SetFileTime returns with
		# error code 6.
		winfile.close(adsH)
		# We just wrote the ADS, so no need for CREATE_ALWAYS
		adsH = winfile.open(getADSPath(f).path, reading=False, writing=True)

		# Set the mtime back to what it was before the ADS was written.
		# We set the mtime on the ADS instead of the file because it
		# might be impossible to open the file with GENERIC_WRITE access
		# if some program has the file open.  Note that timestamps are
		# per-file, not per-stream.
		#
		# Note that if this program is killed during the write() above,
		# the mtime and read-only flags may remain incorrect.
		try:
			winfile.setModificationTimeNanoseconds(adsH, mtime)
		except winfile.SetMetadataFailed:
			writeToStderr("Failed to set modification time on %r" % (f.path,))
			raise
		finally:
			winfile.close(adsH)
		if wasReadOnly:
			os.chmod(f.path, stat.S_IREAD)
	return checksums


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
		return setChecksums(f, verbose)
	except winfile.OpenFailed:
		writeToBothIfVerbose("NOOPEN\t%r" % (f.path,), verbose)
	except winfile.WriteFailed:
		writeToBothIfVerbose("NOWRITE\t%r" % (f.path,), verbose)


highEntropyExtensions = """
	jpeg jpg gif png psd zip zipx z gz bz2 7z xz rar deb rpm apk sitx pkg pptx docx xlsx
	exe pdf epub mobi djvu mp3 mp4 avi m4a m4v mkv ogg webm wmv flac video flv
	mov torrent par2""".split()
lowEntropyExtensions = """
	bmp txt log htm html shtml xhtml svg mht mhtml php cgi rss atom js css py pyc
	pl rb hs el clj cljs c cpp cxx cs lua java sh patch diff ini ico jar tar ppt
	doc xls rtf dll so pyd class o json xml srt csv feed comments nzb lst nfo rdf cdx""".split()

def expectedCompressionState(f):
	ext = f.basename().rsplit('.', 1)[-1].lower()
	if ext in lowEntropyExtensions:
		return "COMPRESSED"
	elif ext in highEntropyExtensions:
		# TODO: look at size-on-disk/file size and don't decompress files that have compressed well
		return "DECOMPRESSED"
	else:
		return "AS_IS"


def getWeirdHexdigest(checksums):
	if checksums is None:
		return '?' * 32
	else:
		m = hashlib.md5()
		for c in checksums:
			m.update(c)
		return m.hexdigest()


def time2iso(t):
	s = datetime.datetime.utcfromtimestamp(t).isoformat()
	if not "." in s:
		s = s + "."
	return s.ljust(26, "0")


def writeListingLine(listing, normalizeListing, baseDir, t, digest, mtime, ctime, size, f):
	if listing is None:
		return

	p = f.path
	if normalizeListing:
		removeMe = baseDir.path + ("\\" if os.name == 'nt' else '/')
		assert p.startswith(removeMe), (p, removeMe)
		p = p.replace(removeMe, "", 1)
		assert len(p) < len(f.path), (p, f.path)
		if os.name == 'nt':
			p = p.replace("\\", "/")

	if size is not None:
		size_s = "{:,d}".format(f.getsize()).rjust(17)
	else:
		size_s = "-".rjust(17)
	return listing.write(" ".join([t, digest, time2iso(mtime), time2iso(ctime), size_s, utf8IfUnicode(p)]) + "\n")


# Four possibilities here:
# verify=False, write=False -> just recurse and print NEW/NOOPEN/NOREAD/MODIFIED
# verify=True, write=False -> verify checksums for non-modified files
# verify=True, write=True -> verify and write new checksums where needed
# verify=False, write=True -> ignore existing checksums, write new checksums where needed
# + compress/decompress as needed

def verifyOrSetChecksums(f, verify, write, compress, inspect, verbose, listing, normalizeListing, baseDir):
	wroteChecksums = None
	detectedCorruption = False
	try:
		# Needed only for decodeBody to work around an old bug
		fileSize = f.getsize()
	except (OSError, IOError):
		writeToBothIfVerbose("NOSTAT\t%r" % (f.path,), verbose)
		return

	try:
		adsR = winfile.open(getADSPath(f).path, reading=True, writing=False)
	except (ADSOnlyOnWindows, winfile.OpenFailed):
		body = None
	else:
		try:
			body = decodeBody(adsR, fileSize)
			mtime = winfile.getModificationTimeNanoseconds(adsR)
		except UnreadableBody:
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
			wroteChecksums = setChecksumsOrPrintMessage(f, verbose)
	elif isinstance(body, StaticBody):
		##print repr(body.mtime), repr(mtime)
		if body.mtime != mtime:
			writeToBothIfVerbose("MODIFIED\t%r" % (f.path,), verbose)
			if write:
				# Existing checksums are probably obsolete, so just
				# set new checksums.
				setChecksumsOrPrintMessage(f, verbose)
		elif verify:
			try:
				h = winfile.open(f.path, reading=True, writing=False)
			except winfile.OpenFailed:
				writeToBothIfVerbose("NOOPEN\t%r" % (f.path,), verbose)
			else:
				try:
					checksums = getChecksums(h)
				except winfile.ReadFailed:
					writeToBothIfVerbose("NOREAD\t%r" % (f.path,), verbose)
				else:
					if checksums != body.checksums:
						detectedCorruption = True
						writeToBothIfVerbose("CORRUPT\t%r" % (f.path,), verbose)
					else:
						if verbose:
							writeToStderr("VERIFIED\t%r" % (f.path,))
				finally:
					winfile.close(h)

	# for VolatileBody, do nothing

	if compress and not detectedCorruption:
		if os.name != 'nt':
			raise RuntimeError("Can't compress on non-Windows")
		expectedComp = expectedCompressionState(f)
		if expectedComp != "AS_IS":
			currentComp = {True: "COMPRESSED", False: "DECOMPRESSED"}[winfile.isCompressed(f.path)]
			if currentComp != expectedComp:
				try:
					h = winfile.open(f.path, reading=True, writing=True)
				except winfile.OpenFailed:
					writeToBothIfVerbose("NOOPEN\t%r" % (f.path,), verbose)
				else:
					try:
						if expectedComp == "COMPRESSED":
							winfile.compress(h)
						elif expectedComp == "DECOMPRESSED":
							winfile.decompress(h)
						if verbose:
							writeToStderr("%s\t%r" % (expectedComp, f.path))
					finally:
						winfile.close(h)

	if listing:
		if wroteChecksums is not None:
			listingChecksums = wroteChecksums
		elif body is not None:
			listingChecksums = body.checksums
		else:
			# In this case, we don't have existing checksums,
			# nor have we written any, so read the file to calculate them.
			try:
				h = winfile.open(f.path, reading=True, writing=False)
			except winfile.OpenFailed:
				listingChecksums = None
			else:
				try:
					listingChecksums = getChecksums(h)
				except winfile.ReadFailed:
					listingChecksums = None
				finally:
					winfile.close(h)

		digest = getWeirdHexdigest(listingChecksums)
		writeListingLine(listing, normalizeListing, baseDir, "F", digest, f.getModificationTime(), f.getStatusChangeTime(), f.getsize(), f)


class SortedListdirFilePath(FilePath):
	"""
	Used to make sure we descend in the same order on different machines
	that have the same copy of the data.
	"""
	def listdir(self):
		paths = os.listdir(self.path)
		# We decode str to Unicode instead of the other way around
		# to avoid potential UTF-8 normalization issues on POSIX.
		# (Note: my POSIX systems use only well-formed UTF-8 filenames)
		if paths and isinstance(paths[0], str):
			paths.sort(key=lambda f: f.decode("utf-8"))
		else:
			paths.sort()
		return paths

SortedListdirFilePath.clonePath = SortedListdirFilePath


def shouldDescend(verbose, f):
	# http://twistedmatrix.com/trac/ticket/5123
	if not f.isdir():
		return False
	excludes = getExcludesForDirectory(winfile.parentEx(f))
	if f.basename() in excludes:
		return False
	# Don't descend any reparse points (symlinks are reparse points too).
	if winfile.isReparsePoint(f):
		return False
	try:
		os.listdir(f.path)
	except OSError: # A "Permission denied" WindowsError, usually
		writeToBothIfVerbose("NOLISTDIR\t%r" % (f.path,), verbose)
		return False
	return True


def handlePath(f, verify, write, compress, inspect, verbose, listing, normalizeListing, baseDir):
	if winfile.isReparsePoint(f):
		# Pretend all reparse points are "S" symlinks, even though they're not
		writeListingLine(listing, normalizeListing, baseDir, "S", "-" * 32, f.getModificationTime(), f.getStatusChangeTime(), None, f)
	elif f.isfile():
		verifyOrSetChecksums(f, verify, write, compress, inspect, verbose, listing, normalizeListing, baseDir)
	elif f.isdir():
		writeListingLine(listing, normalizeListing, baseDir, "D", "-" * 32, f.getModificationTime(), f.getStatusChangeTime(), None, f)
	else:
		writeListingLine(listing, normalizeListing, baseDir, "O", "-" * 32, f.getModificationTime(), f.getStatusChangeTime(), None, f)


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


def reducePriority():
	"""
	Set process priority to IDLE_PRIORITY_CLASS to reduce our CPU and IO priority.
	"""
	if os.name == 'nt':
		import win32api
		import win32con
		import win32process
		pid = win32api.GetCurrentProcessId()
		handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
		win32process.SetPriorityClass(handle, win32process.IDLE_PRIORITY_CLASS)
	else:
		os.nice(5)


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
	parser.add_argument('-c', '--compress', dest='compress', action='store_true',
		help="compress/decompress/do nothing based on probable file entropy")
	parser.add_argument('-i', '--inspect', dest='inspect', action='store_true',
		help="print information about existing checksum data")
	parser.add_argument('-q', '--quiet', dest='verbose', action='store_false',
		default=True, help="don't print important and unimportant messages to stderr")
	parser.add_argument('-l', '--listing', dest='listing',
		default=None, help="generate a file listing into this file (columns: "
			"dentry type, Checksummer-specific checksum, ISO mtime, ISO ctime, size, filename)")
	parser.add_argument('-n', '--normalize-listing', dest='normalizeListing', action='store_true',
		default=False, help="print relative path and / instead of \\ in listing")

	args = parser.parse_args()
	kwargs = dict(
		verify=args.verify,
		write=args.write,
		inspect=args.inspect,
		verbose=args.verbose,
		compress=args.compress,
		normalizeListing=args.normalizeListing,
		listing=open(args.listing, "wb") if args.listing else None
	)

	reducePriority()

	if args.normalizeListing and len(args.path) > 1:
		raise RuntimeError("Can't print normalized listing because "
			"more than one path was given: %r" % (args.path,))

	for fname in args.path:
		if os.name == 'nt':
			# Must convert path like C: to C:\, because C: means "the
			# current directory for the C:" drive.  And we must do this
			# before turning it into a FilePath because FilePath will
			# immediately turn C: into C:\some-path
			if fname.endswith(":"):
				fname += "\\"

			# *must* use a unicode path because listdir'ing a `str` extended path
			# raises WindowsError.
			p = winfile.upgradeFilepath(SortedListdirFilePath(fname.decode("ascii")))
		else:
			p = SortedListdirFilePath(fname)

		if p.isdir():
			for f in p.walk(descend=functools.partial(shouldDescend, args.verbose)):
				excludes = getExcludesForDirectory(winfile.parentEx(f))
				if f.basename() not in excludes:
					if f == p:
						continue
					handlePath(f, baseDir=p, **kwargs)
		else:
			f = p
			excludes = getExcludesForDirectory(winfile.parentEx(f))
			if f.basename() not in excludes:
				handlePath(f, baseDir=p, **kwargs)

	writeToBothIfVerbose("FINISHED", args.verbose)


try:
	from refbinder.api import bindRecursive, enableBinders
except ImportError:
	pass
else:
	enableBinders()
	bindRecursive(sys.modules[__name__], _postImportVars + ["SortedListdirFilePath"])


if __name__ == '__main__':
	main()
