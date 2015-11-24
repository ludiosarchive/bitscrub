#!/usr/bin/python

"""
bitscrub

TODO:

*	Support passing in a "file exclude function"; function is called for every
	file; if return value is True, do scan the file.

*	Notice when the mtime changes while the file is being read, and do
	something different.
"""

import os
import stat
import sys
import struct
import time
import datetime
import functools
import operator
import argparse
from cffi import FFI
ffi = FFI()
from _crc32c.lib import sse4_crc32c
import xattr
from twisted.python.filepath import FilePath, LinkError


XATTR_NAME = "user._C"
VERSION = chr(11)


class ChecksumData(tuple):
	__slots__ = ()
	_MARKER = object()

	time_marked = property(operator.itemgetter(1))
	mtime = property(operator.itemgetter(2))
	checksum = property(operator.itemgetter(3))

	def __new__(cls, time_marked, mtime, checksum):
		return tuple.__new__(cls, (cls._MARKER, time_marked, mtime, checksum))


	def __repr__(self):
		return '%s(%r, %r, %r)' % (self.__class__.__name__, self[1], self[2], self[3])


	def get_description(self):
		marked_str = datetime.datetime.utcfromtimestamp(self.time_marked).isoformat()
		mtime_str = datetime.datetime.utcfromtimestamp(self.mtime).isoformat()
		return "<ChecksumData marked at %s when mtime was %s; checksum=%r>" % (
			marked_str, mtime_str, format(self.checksum, '08X'))


	def encode(self):
		return (
			VERSION +
			struct.pack("<d", self.time_marked) +
			struct.pack("<d", self.mtime) +
			struct.pack("<I", self.checksum))



class UnreadableBody(Exception):
	pass


def utf8_if_unicode(s_or_u):
	if isinstance(s_or_u, unicode):
		return s_or_u.encode("utf-8")
	else:
		return s_or_u


def decode_body(body):
	pos = 0
	version_s = body[pos:pos + 1]
	pos += 1
	if not version_s:
		raise UnreadableBody("Body is empty")
	version = ord(version_s)
	if version < 11:
		raise UnreadableBody("Can't read version %r" % (version,))
	time_marked = struct.unpack("<d", body[pos:pos + 8])[0]
	pos += 8
	mtime = struct.unpack("<d", body[pos:pos + 8])[0]
	pos += 8
	checksum = struct.unpack("<I", body[pos:pos + 4])[0]
	pos += 4
	return ChecksumData(time_marked, mtime, checksum)


block_size = 64*1024
# We have single-threaded operation, so we can use the same block of memory
mem = ffi.new('char[%d]' % block_size)
arr = ffi.buffer(mem)

def crc32c_for_file(h):
	c = 0
	while True:
		num_bytes_read = h.readinto(arr)
		if num_bytes_read == 0:
			break
		c = sse4_crc32c(c, mem, num_bytes_read)
	return c


def set_checksum(h, verbose):
	time_marked = time.time()
	fstat = os.fstat(h.fileno())
	mtime = fstat.st_mtime
	checksum = crc32c_for_file(h)
	cd = ChecksumData(time_marked, mtime, checksum)

	mode = fstat.st_mode
	was_read_only = not mode & stat.S_IWRITE
	if was_read_only:
		# We need to unset the read-only flag before we can write a xattr
		try:
			os.fchmod(h.fileno(), mode | stat.S_IWRITE)
		except OSError:
			write_to_both_if_verbose("NOCHMOD\t%r" % (h.name,), verbose)
			return checksum
	xattr._fsetxattr(h.fileno(), XATTR_NAME, cd.encode())
	if was_read_only:
		os.fchmod(h.fileno(), mode)
	return checksum


def write_to_both_if_verbose(msg, verbose):
	sys.stdout.write(msg + "\n")
	sys.stdout.flush()
	if verbose:
		sys.stderr.write(msg + "\n")
		sys.stderr.flush()


def write_to_stdout(msg):
	sys.stdout.write(msg + "\n")
	sys.stdout.flush()


def write_to_stderr(msg):
	sys.stderr.write(msg + "\n")
	sys.stderr.flush()


def time2iso(t):
	s = datetime.datetime.utcfromtimestamp(t).isoformat()
	if not "." in s:
		s = s + "."
	return s.ljust(26, "0")


def write_listing_line(listing, normalize_listing, base_dir, t, checksum, size, f):
	if listing is None:
		return

	p = f.path
	mtime = os.lstat(f.path)
	if normalize_listing:
		remove_me = base_dir.path + '/'
		assert p.startswith(remove_me), (p, remove_me)
		p = p.replace(remove_me, "", 1)
		assert len(p) < len(f.path), (p, f.path)

	if size is not None:
		size_s = "{:,d}".format(f.getsize()).rjust(17)
	else:
		size_s = "-".rjust(17)
	listing.write(" ".join([t, format(checksum, '08X') if checksum is not None else '-' * 8, time2iso(mtime), size_s, utf8_if_unicode(p)]) + "\n")
	listing.flush()


seen_inodes = set()

# Four possibilities here:
# verify=False, write=False -> just recurse and print NEW/NOOPEN/NOREAD/MODIFIED
# verify=True, write=False -> verify checksums for non-modified files
# verify=True, write=True -> verify and write new checksums where needed
# verify=False, write=True -> ignore existing checksums, write new checksums where needed

def verify_or_set_checksum(h, verify, write, inspect, verbose, listing, normalize_listing, base_dir):
	wrote_checksum = None
	fstat = os.fstat(h.fileno())
	if fstat.st_ino in seen_inodes:
		if verbose:
			# No need to check inodes we've already checked
			write_to_stderr("HARDLINK\t%r" % (h.name,))
		return
	seen_inodes.add(fstat.st_ino)
	try:
		encoded_body = xattr._fgetxattr(h.fileno(), XATTR_NAME)
	except IOError: # raised if no xattr by that name
		body = None
	else:
		try:
			body = decode_body(encoded_body)
		except UnreadableBody:
			body = None

	if inspect:
		write_to_stdout("INSPECT\t%r" % (h.name,))
		write_to_stdout("#\t%s" % (body.get_description() if body else repr(body),))
	if body is None:
		if verbose:
			write_to_stderr("NEW\t%r" % (h.name,))
		if write:
			wrote_checksum = set_checksum(h, verbose)
	else:
		if body.mtime != fstat.st_mtime:
			write_to_both_if_verbose("MODIFIED\t%r" % (h.name,), verbose)
			if write:
				# Existing checksum is probably obsolete, so just
				# set new checksum.
				set_checksum(h, verbose)
		elif verify:
			checksum = crc32c_for_file(h)
			if checksum != body.checksum:
				write_to_both_if_verbose("CORRUPT\t%r" % (h.name,), verbose)
			else:
				if verbose:
					write_to_stderr("VERIFIED\t%r" % (h.name,))

	if listing:
		if wrote_checksum is not None:
			listing_checksum = wrote_checksum
		elif body is not None:
			listing_checksum = body.checksum
		else:
			# We don't have an existing checksum, nor did we just write one
			listing_checksum = None

		s = os.lstat(f.path)
		write_listing_line(listing, normalize_listing, base_dir, "F", listing_checksum, f.getsize(), f)


class BetterFilePath(FilePath):
	"""
	A FilePath that sorts the listdir() output to make make sure we descend in
	the same order on different machines that have the same copy of the data.

	Also includes a fixed walk().
	"""
	def listdir(self):
		paths = os.listdir(self.path)
		paths.sort()
		return paths

	def walk(self, descend=None):
		"""
		A less-busted walk() that calls descend on the FilePath itself before descending.

		Also removes the broken cycle check that assumes there are cycles when
		they would be stopped by a `descend` call.

		Also avoids calling `descend` function on non-directories.
		"""
		yield self
		if not self.isdir():
			return
		if descend is not None and not descend(self):
			return
		for c in self.children():
			if c.isdir() and (descend is None or descend(c)):
				for subc in c.walk(descend):
					yield subc
			else:
				yield c


BetterFilePath.clonePath = BetterFilePath


def should_descend(verbose, f):
	#print "should_descend", f, f.islink()
	# Don't descend symlinks
	if f.islink():
		return False
	try:
		f.listdir()
	except OSError: # A "Permission denied" error, usually
		write_to_both_if_verbose("NOLISTDIR\t%r" % (f.path,), verbose)
		return False
	return True


def handle_path(f, verify, write, inspect, verbose, listing, normalize_listing, base_dir):
	if f.islink():
		write_listing_line(listing, normalize_listing, base_dir, "S", None, None, f)
	elif f.isfile():
		try:
			h = open(f.path, 'rb')
		except (OSError, IOError):
			write_to_both_if_verbose("NOOPEN\t%r" % (f.path,), verbose)
		else:
			try:
				verify_or_set_checksum(h, verify, write, inspect, verbose, listing, normalize_listing, base_dir)
			finally:
				h.close()
	elif f.isdir():
		write_listing_line(listing, normalize_listing, base_dir, "D", None, None, f)
	else:
		write_listing_line(listing, normalize_listing, base_dir, "O", None, None, f)


def main():
	parser = argparse.ArgumentParser(description="""
	Walks a directory tree and reads and/or writes the CRC32C of each file
	to a xattr "%s".  Useful for detecting bitrot.

	--verify, --write, and --inspect can be combined.  If none of these are
	specified, files will be checked only for lack of checksum data or updated mtime.
	""" % (XATTR_NAME,))

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
		default=True, help="don't print both important and unimportant messages to stderr; still print important messages to stdout")
	parser.add_argument('-l', '--listing', dest='listing',
		default=None, help="generate a file listing into this file (columns: "
			"dentry type, CRC32C, mtime, size, filename)")
	parser.add_argument('-n', '--normalize-listing', dest='normalize_listing', action='store_true',
		default=False, help="print relative path")

	args = parser.parse_args()
	kwargs = dict(
		verify=args.verify,
		write=args.write,
		inspect=args.inspect,
		verbose=args.verbose,
		normalize_listing=args.normalize_listing,
		listing=open(args.listing, "wb") if args.listing else None
	)

	os.nice(5)

	if args.normalize_listing and len(args.path) > 1:
		raise RuntimeError("Can't print normalized listing because "
			"more than one path was given: %r" % (args.path,))

	for fname in args.path:
		p = BetterFilePath(fname)
		print p

		if p.isdir():
			for f in p.walk(descend=functools.partial(should_descend, args.verbose)):
				assert isinstance(f, BetterFilePath), type(f)
				if f == p:
					continue
				handle_path(f, base_dir=p, **kwargs)
		else:
			f = p
			handle_path(f, base_dir=p, **kwargs)

	write_to_both_if_verbose("FINISHED", args.verbose)


if __name__ == '__main__':
	main()
