#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import unittest

suite = unittest.TestLoader().loadTestsFromNames(
    ['tests.codec.json.test_encoder.suite',
     'tests.codec.json.test_decoder.suite']
)

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
