from twisted.trial import unittest

from checksummer import scan

import hashlib
from StringIO import StringIO as S


def d(s):
	return hashlib.md5(s).digest()[:8]


class GetChecksumsTests(unittest.TestCase):

	def _testWithReadLength(self, n):
		self.assertEqual([], list(scan._getChecksums(S(""), n, 4)))
		self.assertEqual([d("a")], list(scan._getChecksums(S("a"), n, 4)))
		self.assertEqual([d("ab")], list(scan._getChecksums(S("ab"), n, 4)))
		self.assertEqual([d("abcd")], list(scan._getChecksums(S("abcd"), n, 4)))
		self.assertEqual([d("abcd"), d("e")], list(scan._getChecksums(S("abcde"), n, 4)))
		self.assertEqual([d("abcd"), d("efgh")], list(scan._getChecksums(S("abcdefgh"), n, 4)))


	def test_getChecksumsSmallerReadLength(self):
		self._testWithReadLength(2)


	def test_getChecksumsEqualReadLength(self):
		self._testWithReadLength(4)
