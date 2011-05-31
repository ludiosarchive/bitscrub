from twisted.trial import unittest

import win32file

from checksummer import winfile


class WinFileTests(unittest.TestCase):

	def test_reading_writing(self):
		temp = self.mktemp().decode("ascii") # Let's just hope we can decode
		h = winfile.open(temp, reading=True, writing=True,
			creationDisposition=win32file.OPEN_ALWAYS)
		winfile.write(h, "hello world\n")
	
		self.assertEqual(12, winfile.getFileSize(h))

		winfile.seek(h, 0)
		out = winfile.read(h, 12)
		self.assertEqual("hello world\n", out)

		winfile.seek(h, 6)
		out = winfile.read(h, 6)
		self.assertEqual("world\n", out)

		# Read more than available
		winfile.seek(h, 0)
		out = winfile.read(h, 15)
		self.assertEqual("hello world\n", out)

		winfile.seek(h, -2, 2)
		out = winfile.read(h, 2)
		self.assertEqual("d\n", out)

		out = winfile.read(h, 2)
		self.assertEqual("", out)

		# Try some incremental reading
		winfile.seek(h, 0)
		self.assertEqual("hello ", winfile.read(h, 6))
		self.assertEqual("world\n", winfile.read(h, 6))

		# Smaller incremental reading
		winfile.seek(h, 0)
		self.assertEqual("h", winfile.read(h, 1))
		self.assertEqual("e", winfile.read(h, 1))
		self.assertEqual("l", winfile.read(h, 1))

		winfile.close(h)


	def test_reading_writing_null(self):
		temp = self.mktemp().decode("ascii") # Let's just hope we can decode
		h = winfile.open(temp, reading=True, writing=True,
			creationDisposition=win32file.OPEN_ALWAYS)
		winfile.write(h, "hello\x00world\n")
		self.assertEqual(12, winfile.getFileSize(h))
		winfile.seek(h, 0)
		self.assertEqual("hello\x00world\n", winfile.read(h, 12))


	def test_reading_ads(self):
		temp = self.mktemp().decode("ascii") + u":DEMO_ADS"
		h = winfile.open(temp, reading=True, writing=True,
			creationDisposition=win32file.OPEN_ALWAYS)
		winfile.write(h, "hello world\n")
		winfile.close(h)

		h = winfile.open(temp, reading=True, writing=False,
			creationDisposition=win32file.OPEN_EXISTING)
		winfile.seek(h, 0)
		self.assertEqual("h", winfile.read(h, 1))
		self.assertEqual("e", winfile.read(h, 1))
		self.assertEqual("l", winfile.read(h, 1))


	def test_modificationTime(self):
		temp = self.mktemp().decode("ascii") # Let's just hope we can decode
		h = winfile.open(temp, reading=False, writing=True,
			creationDisposition=win32file.OPEN_ALWAYS)

		now = winfile.getModificationTimeNanoseconds(h)
		self.assertTrue(now > 1000000000000, now) # probably even larger

		winfile.setModificationTimeNanoseconds(h, 1)	
		now = winfile.getModificationTimeNanoseconds(h)
		self.assertEqual(1, now)
