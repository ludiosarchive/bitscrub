from twisted.trial import unittest

import win32file

from checksummer import winfile


class WinFileTests(unittest.TestCase):

	def test_reading_writing(self):
		temp = self.mktemp().decode("ascii") # Let's just hope we can decode
		h = winfile.open(temp, reading=True, writing=True,
			creationDisposition=win32file.OPEN_ALWAYS)
		winfile.write(h, "hello world\n")
	
		winfile.seek(h, 0)
		out = winfile.read(h, 12)
		self.assertEqual("hello world\n", out)

		winfile.seek(h, 6)
		out = winfile.read(h, 6)
		self.assertEqual("world\n", out)

		winfile.seek(h, -2, 2)
		out = winfile.read(h, 2)
		self.assertEqual("d\n", out)

		out = winfile.read(h, 2)
		self.assertEqual("", out)

		winfile.close(h)


	def test_modificationTime(self):
		temp = self.mktemp().decode("ascii") # Let's just hope we can decode
		h = winfile.open(temp, reading=False, writing=True,
			creationDisposition=win32file.OPEN_ALWAYS)

		now = winfile.getModificationTimeNanoseconds(h)
		self.assertTrue(now > 1000000000000, now) # probably even larger

		winfile.setModificationTimeNanoseconds(h, 1)	
		now = winfile.getModificationTimeNanoseconds(h)
		self.assertEqual(1, now)
