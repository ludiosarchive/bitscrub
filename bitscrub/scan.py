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

_postImportVars = vars().keys()


XATTR_NAME = "_C"
VERSION = chr(1)


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


	def get_description(self):
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


	def get_description(self):
		markedStr = datetime.datetime.utcfromtimestamp(self.timeMarked).isoformat()
		return "<VolatileBody marked at %s>" % (markedStr,)


	def encode(self):
		return VERSION + "\x01" + struct.pack("<d", self.timeMarked)


def getADSPath(f):
	return FilePath(f.path + ADS_COLON + ADS_NAME)


class UnreadableBody(Exception):
	pass


def utf8_if_unicode(s_or_u):
	if isinstance(s_or_u, unicode):
		return s_or_u.encode("utf-8")
	else:
		return s_or_u


def decode_body(h, fileSize):
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


def _get_checksums(h, readSize, blockSize):
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


def get_checksums(h):
	return list(_get_checksums(h, readSize=32*1024, blockSize=32*1024*1024))


def set_checksums(f, verbose):
	timeMarked = time.time()

	try:
		h = winfile.open(f.path, reading=True, writing=False)
	except winfile.OpenFailed:
		writeToBothIfVerbose("NOOPEN\t%r" % (f.path,), verbose)
		return None
	try:
		checksums = get_checksums(h)
		mtime = winfile.getModificationTimeNanoseconds(h)
	except winfile.ReadFailed:
		writeToBothIfVerbose("NOREAD\t%r" % (f.path,), verbose)
		return None
	except winfile.SeekFailed, e:
		print repr(e)
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


def set_checksums_or_print_message(f, verbose):
	try:
		return set_checksums(f, verbose)
	except winfile.OpenFailed:
		writeToBothIfVerbose("NOOPEN\t%r" % (f.path,), verbose)
	except winfile.WriteFailed:
		writeToBothIfVerbose("NOWRITE\t%r" % (f.path,), verbose)


def get_weird_hexdigest(checksums):
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


def write_listing_line(listing, normalize_listing, base_dir, t, digest, mtime, ctime, size, f):
	if listing is None:
		return

	p = f.path
	if normalize_listing:
		removeMe = base_dir.path + '/'
		assert p.startswith(removeMe), (p, removeMe)
		p = p.replace(removeMe, "", 1)
		assert len(p) < len(f.path), (p, f.path)

	if size is not None:
		size_s = "{:,d}".format(f.getsize()).rjust(17)
	else:
		size_s = "-".rjust(17)
	listing.write(" ".join([t, digest, time2iso(mtime), time2iso(ctime), size_s, utf8_if_unicode(p)]) + "\n")
	listing.flush()


# Four possibilities here:
# verify=False, write=False -> just recurse and print NEW/NOOPEN/NOREAD/MODIFIED
# verify=True, write=False -> verify checksums for non-modified files
# verify=True, write=True -> verify and write new checksums where needed
# verify=False, write=True -> ignore existing checksums, write new checksums where needed
# + compress/decompress as needed

def verify_or_set_checksums(f, verify, write, inspect, verbose, listing, normalize_listing, base_dir):
	wroteChecksums = None
	detectedCorruption = False
	try:
		# Needed only for decode_body to work around an old bug
		fileSize = f.getsize()
	except (OSError, IOError):
		writeToBothIfVerbose("NOSTAT\t%r" % (f.path,), verbose)
		return

	try:
		adsR = winfile.open(getADSPath(f).path, reading=True, writing=False)
	except winfile.OpenFailed:
		body = None
	else:
		try:
			body = decode_body(adsR, fileSize)
			mtime = os.stat(f.path).st_mtime
		except UnreadableBody:
			body = None
		finally:
			winfile.close(adsR)

	if inspect:
		writeToStdout("INSPECT\t%r" % (f.path,))
		writeToStdout("#\t%s" % (body.get_description() if body else repr(body),))
	if body is None:
		if verbose:
			writeToStderr("NEW\t%r" % (f.path,))
		if write:
			wroteChecksums = set_checksums_or_print_message(f, verbose)
	elif isinstance(body, StaticBody):
		##print repr(body.mtime), repr(mtime)
		if body.mtime != mtime:
			writeToBothIfVerbose("MODIFIED\t%r" % (f.path,), verbose)
			if write:
				# Existing checksums are probably obsolete, so just
				# set new checksums.
				set_checksums_or_print_message(f, verbose)
		elif verify:
			try:
				h = winfile.open(f.path, reading=True, writing=False)
			except winfile.OpenFailed:
				writeToBothIfVerbose("NOOPEN\t%r" % (f.path,), verbose)
			else:
				try:
					checksums = get_checksums(h)
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
					listingChecksums = get_checksums(h)
				except winfile.ReadFailed:
					listingChecksums = None
				finally:
					winfile.close(h)

		digest = get_weird_hexdigest(listingChecksums)
		s = os.lstat(f.path)
		write_listing_line(listing, normalize_listing, base_dir, "F", digest, s.st_mtime, s.st_ctime, f.getsize(), f)


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


def should_descend(verbose, f):
	# http://twistedmatrix.com/trac/ticket/5123
	if not f.isdir():
		return False
	excludes = get_excludes_for_directory(winfile.parentEx(f))
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


def handle_path(f, verify, write, inspect, verbose, listing, normalize_listing, base_dir):
	s = os.lstat(f.path)
	if winfile.isReparsePoint(f):
		# Pretend all reparse points are "S" symlinks, even though they're not
		write_listing_line(listing, normalize_listing, base_dir, "S", "-" * 32, s.st_mtime, s.st_ctime, None, f)
	elif f.isfile():
		verify_or_set_checksums(f, verify, write, inspect, verbose, listing, normalize_listing, base_dir)
	elif f.isdir():
		write_listing_line(listing, normalize_listing, base_dir, "D", "-" * 32, s.st_mtime, s.st_ctime, None, f)
	else:
		write_listing_line(listing, normalize_listing, base_dir, "O", "-" * 32, s.st_mtime, s.st_ctime, None, f)


def get_content_if_exists(f, maxRead):
	try:
		h = winfile.open(f.path, reading=True, writing=False)
	except winfile.OpenFailed:
		return None
	try:
		return winfile.read(h, maxRead)
		# Above might raise exception if .read() fails for some reason
	finally:
		winfile.close(h)


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
	parser.add_argument('-l', '--listing', dest='listing',
		default=None, help="generate a file listing into this file (columns: "
			"dentry type, Checksummer-specific checksum, ISO mtime, ISO ctime, size, filename)")
	parser.add_argument('-n', '--normalize-listing', dest='normalize_listing', action='store_true',
		default=False, help="print relative path")

	args = parser.parse_args()
	kwargs = dict(
		verify=args.verify,
		write=args.write,
		inspect=args.inspect,
		verbose=args.verbose,
		compress=args.compress,
		normalize_listing=args.normalize_listing,
		listing=open(args.listing, "wb") if args.listing else None
	)

	os.nice(5)

	if args.normalize_listing and len(args.path) > 1:
		raise RuntimeError("Can't print normalized listing because "
			"more than one path was given: %r" % (args.path,))

	for fname in args.path:
		p = SortedListdirFilePath(fname)
		print p

		if p.isdir():
			for f in p.walk(descend=functools.partial(should_descend, args.verbose)):
				assert isinstance(f, SortedListdirFilePath), type(f)
				if f == p:
					continue
				handle_path(f, base_dir=p, **kwargs)
		else:
			f = p
			handle_path(f, base_dir=p, **kwargs)

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
