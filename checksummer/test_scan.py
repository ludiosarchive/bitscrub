from twisted.trial import unittest

from checksummer import scan

from StringIO import StringIO as S


class GetChecksumsTests(unittest.TestCase):

	def test_getChecksums(self):
		self.assertEqual(0, len(list(scan._getChecksums(S(""), 2, 4))))
		self.assertEqual(1, len(list(scan._getChecksums(S("a"), 2, 4))))
		self.assertEqual(1, len(list(scan._getChecksums(S("abcd"), 2, 4))))
		self.assertEqual(2, len(list(scan._getChecksums(S("abcde"), 2, 4))))
