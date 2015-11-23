from twisted.trial import unittest
from twisted.python.filepath import FilePath

from checksummer import scan
from checksummer import winfile

import hashlib


def d(s):
	return hashlib.md5(s).digest()[:8]


def S(s, mktemp):
	temp = mktemp().decode("ascii")
	FilePath(temp).setContent(s)
	return winfile.open(temp, reading=True, writing=False)
	# File handles are leaked


class GetChecksumsTests(unittest.TestCase):

	def _testWithReadLength(self, n):
		t = self.mktemp
		self.assertEqual([], list(scan._getChecksums(S("", t), n, 4)))
		self.assertEqual([d("a")], list(scan._getChecksums(S("a", t), n, 4)))
		self.assertEqual([d("ab")], list(scan._getChecksums(S("ab", t), n, 4)))
		self.assertEqual([d("abcd")], list(scan._getChecksums(S("abcd", t), n, 4)))
		self.assertEqual([d("abcd"), d("e")], list(scan._getChecksums(S("abcde", t), n, 4)))
		self.assertEqual([d("abcd"), d("efgh")], list(scan._getChecksums(S("abcdefgh", t), n, 4)))


	def test_getChecksumsSmallerReadLength(self):
		self._testWithReadLength(2)


	def test_getChecksumsEqualReadLength(self):
		self._testWithReadLength(4)
