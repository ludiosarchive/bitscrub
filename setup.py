#!/usr/bin/env python3

import os
import sys
from distutils.core import setup

from bitscrub import __version__

setup(
	name="bitscrub",
	version=__version__,
	description="writes and verifies whole-file CRC32C checksums stored in a xattr",
	url="https://github.com/ludios/bitscrub",
	author="Ivan Kozik",
	author_email="ivan@ludios.org",
	classifiers=[
		"Programming Language :: Python :: 3",
		"Development Status :: 5 - Production/Stable",
		"Operating System :: POSIX :: Linux",
		"Intended Audience :: System Administrators",
		"License :: OSI Approved :: MIT License",
	],
	packages=["bitscrub"],
	install_requires=["pycrc32c", "xattr", "cffi"]
)
