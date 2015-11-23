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
import hashlib
import xattr
from twisted.python.filepath import FilePath


XATTR_NAME = "user._C"
VERSION = chr(9)


class StaticBody(tuple):
	__slots__ = ()
	_MARKER = object()

	time_marked = property(operator.itemgetter(1))
	mtime = property(operator.itemgetter(2))
	checksums = property(operator.itemgetter(3))

	def __new__(cls, time_marked, mtime, checksums):
		return tuple.__new__(cls, (cls._MARKER, time_marked, mtime, checksums))


	def __repr__(self):
		return '%s(%r, %r, %r)' % (self.__class__.__name__, self[1], self[2], self[3])


	def get_description(self):
		marked_str = datetime.datetime.utcfromtimestamp(self.time_marked).isoformat()
		mtime_str = datetime.datetime.utcfromtimestamp(self.mtime).isoformat()
		checksums_hex = list(s.encode("hex") for s in self.checksums)
		return "<StaticBody marked at %s when mtime was %s; checksums=%r>" % (
			marked_str, mtime_str, checksums_hex)


	def encode(self):
		return (
			VERSION +
			"\x00" +
			struct.pack("<d", self.time_marked) +
			struct.pack("<d", self.mtime) +
			"".join(self.checksums))



class VolatileBody(tuple):
	__slots__ = ()
	_MARKER = object()

	time_marked = property(operator.itemgetter(1))

	def __new__(cls, time_marked):
		return tuple.__new__(cls, (cls._MARKER, time_marked))


	def __repr__(self):
		return '%s(%r)' % (self.__class__.__name__, self[1])


	def get_description(self):
		marked_str = datetime.datetime.utcfromtimestamp(self.time_marked).isoformat()
		return "<VolatileBody marked at %s>" % (marked_str,)


	def encode(self):
		return VERSION + "\x01" + struct.pack("<d", self.time_marked)


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
	if version < 9:
		raise UnreadableBody("Can't read version %r" % (version,))
	volatile_str = body[pos:pos + 1]
	pos += 1
	if not volatile_str:
		raise UnreadableBody("Truncated xattr value?")
	is_volatile = bool(ord(volatile_str))
	time_marked = struct.unpack("<d", body[pos:pos + 8])[0]
	pos += 8
	mtime = struct.unpack("<d", body[pos:pos + 8])[0]
	pos += 8
	if not is_volatile:
		checksums = []
		while True:
			c = body[pos:pos + 8]
			pos += 8
			assert len(c) in (0, 8), "Got %d bytes instead of expected 0 or 8: %r" % (len(c), c)
			if not c:
				break
			checksums.append(c)
		return StaticBody(time_marked, mtime, checksums)
	else:
		return VolatileBody(time_marked)


def _get_checksums(h, read_size, block_size):
	"""
	Yields an 8-byte hash for every `block_size` bytes in `h`.
	Doesn't yield anything for an empty file.  Yields one hash for
	a `block_size`-sized file.
	"""
	if block_size % read_size != 0:
		raise ValueError("block_size must be divisible by read_size; "
			"arguments were read_size=%r, block_size=%r)" % (read_size, block_size))

	h.seek(0)
	pos = 0
	m = hashlib.md5()
	block_in_progress = False
	while True:
		data = h.read(read_size)
		pos += len(data)
		if not data:
			if block_in_progress:
				yield m.digest()[:8]
			break
		m.update(data)
		if len(data) < read_size:
			yield m.digest()[:8]
			break
		elif pos % block_size == 0:
			yield m.digest()[:8]
			m = hashlib.md5()
			block_in_progress = False
		else:
			block_in_progress = True


def get_checksums(h):
	return list(_get_checksums(h, read_size=32*1024, block_size=32*1024*1024))


def set_checksums(f, verbose):
	time_marked = time.time()

	try:
		h = open(f.path, 'rb')
	except (OSError, IOError):
		# IOError raised if we have no permission
		write_to_both_if_verbose("NOOPEN\t%r" % (f.path,), verbose)
		return None
	fstat = os.stat(f.path)
	try:
		checksums = get_checksums(h)
		mtime = fstat.st_mtime
	except OSError:
		write_to_both_if_verbose("NOREAD\t%r" % (f.path,), verbose)
		return None
	finally:
		h.close()
	sb = StaticBody(time_marked, mtime, checksums)

	mode = fstat.st_mode
	was_read_only = not mode & stat.S_IWRITE
	if was_read_only:
		# We need to unset the read-only flag before we can write a xattr
		try:
			os.chmod(f.path, mode | stat.S_IWRITE)
		except OSError:
			write_to_both_if_verbose("NOCHMOD\t%r" % (f.path,), verbose)
			return checksums
	xattr.setxattr(f.path, XATTR_NAME, sb.encode())
	if was_read_only:
		os.chmod(f.path, mode)
	return checksums


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


def set_checksums_or_print_message(f, verbose):
	try:
		return set_checksums(f, verbose)
	except OSError:
		write_to_both_if_verbose("NOOPEN\t%r" % (f.path,), verbose)


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


def write_listing_line(listing, normalize_listing, base_dir, t, digest, mtime, size, f):
	if listing is None:
		return

	p = f.path
	if normalize_listing:
		remove_me = base_dir.path + '/'
		assert p.startswith(remove_me), (p, remove_me)
		p = p.replace(remove_me, "", 1)
		assert len(p) < len(f.path), (p, f.path)

	if size is not None:
		size_s = "{:,d}".format(f.getsize()).rjust(17)
	else:
		size_s = "-".rjust(17)
	listing.write(" ".join([t, digest, time2iso(mtime), size_s, utf8_if_unicode(p)]) + "\n")
	listing.flush()


# Four possibilities here:
# verify=False, write=False -> just recurse and print NEW/NOOPEN/NOREAD/MODIFIED
# verify=True, write=False -> verify checksums for non-modified files
# verify=True, write=True -> verify and write new checksums where needed
# verify=False, write=True -> ignore existing checksums, write new checksums where needed

def verify_or_set_checksums(f, verify, write, inspect, verbose, listing, normalize_listing, base_dir):
	wrote_checksums = None
	detected_corruption = False
	try:
		encoded_body = xattr.getxattr(f.path, XATTR_NAME)
	except IOError:
		body = None
	else:
		try:
			body = decode_body(encoded_body)
			mtime = os.stat(f.path).st_mtime
		except UnreadableBody:
			body = None

	if inspect:
		write_to_stdout("INSPECT\t%r" % (f.path,))
		write_to_stdout("#\t%s" % (body.get_description() if body else repr(body),))
	if body is None:
		if verbose:
			write_to_stderr("NEW\t%r" % (f.path,))
		if write:
			wrote_checksums = set_checksums_or_print_message(f, verbose)
	elif isinstance(body, StaticBody):
		##print repr(body.mtime), repr(mtime)
		if body.mtime != mtime:
			write_to_both_if_verbose("MODIFIED\t%r" % (f.path,), verbose)
			if write:
				# Existing checksums are probably obsolete, so just
				# set new checksums.
				set_checksums_or_print_message(f, verbose)
		elif verify:
			try:
				h = open(f.path, 'rb')
			except OSError:
				write_to_both_if_verbose("NOOPEN\t%r" % (f.path,), verbose)
			else:
				try:
					checksums = get_checksums(h)
				except OSError:
					write_to_both_if_verbose("NOREAD\t%r" % (f.path,), verbose)
				else:
					if checksums != body.checksums:
						detected_corruption = True
						write_to_both_if_verbose("CORRUPT\t%r" % (f.path,), verbose)
					else:
						if verbose:
							write_to_stderr("VERIFIED\t%r" % (f.path,))
				finally:
					h.close()
	# for VolatileBody, do nothing

	if listing:
		if wrote_checksums is not None:
			listing_checksums = wrote_checksums
		elif body is not None:
			listing_checksums = body.checksums
		else:
			# In this case, we don't have existing checksums,
			# nor have we written any, so read the file to calculate them.
			try:
				h = open(f.path, 'rb')
			except OSError:
				listing_checksums = None
			else:
				try:
					listing_checksums = get_checksums(h)
				except OSError:
					listing_checksums = None
				finally:
					h.close()

		digest = get_weird_hexdigest(listing_checksums)
		s = os.lstat(f.path)
		write_listing_line(listing, normalize_listing, base_dir, "F", digest, s.st_mtime, f.getsize(), f)


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
	# Don't descend symlinks
	if os.path.islink(f.path):
		return False
	try:
		os.listdir(f.path)
	except OSError: # A "Permission denied" WindowsError, usually
		write_to_both_if_verbose("NOLISTDIR\t%r" % (f.path,), verbose)
		return False
	return True


def handle_path(f, verify, write, inspect, verbose, listing, normalize_listing, base_dir):
	s = os.lstat(f.path)
	if os.path.islink(f.path):
		write_listing_line(listing, normalize_listing, base_dir, "S", "-" * 32, s.st_mtime, None, f)
	elif f.isfile():
		verify_or_set_checksums(f, verify, write, inspect, verbose, listing, normalize_listing, base_dir)
	elif f.isdir():
		write_listing_line(listing, normalize_listing, base_dir, "D", "-" * 32, s.st_mtime, None, f)
	else:
		write_listing_line(listing, normalize_listing, base_dir, "O", "-" * 32, s.st_mtime, None, f)


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
		default=True, help="don't print important and unimportant messages to stderr")
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

	write_to_both_if_verbose("FINISHED", args.verbose)


if __name__ == '__main__':
	main()
