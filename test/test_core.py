# Copyright (C) 2014 Peter Todd <pete@petertodd.org>
#
# This file is part of python-smartcolors.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-smartcolors, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import io
import unittest

from proofmarshal import *
from proofmarshal.test import load_test_vectors, x, b2x

class boxed_varuint(ImmutableProof):
    """Dummy object with a single varuint in it"""

    def __init__(self, i):
        object.__setattr__(self, 'i', i)

    def ctx_serialize(self, ctx):
        ctx.write_varuint('i', self.i)

    def ctx_deserialize(self, ctx):
        object.__setattr__(self, 'i', ctx.read_varuint('i'))


class Test_BytesSerializationContext(unittest.TestCase):
    def test_varuint(self):
        """Test varuints against vectors"""

        for expected_hex_bytes, expected_value in load_test_vectors('valid_varuints.json'):
            expected_bytes = x(expected_hex_bytes)

            # serialize
            actual_bytes = boxed_varuint(expected_value).serialize()
            self.assertEqual(b2x(expected_bytes), b2x(actual_bytes))

            # deserialize
            actual_value = boxed_varuint.deserialize(expected_bytes).i
            self.assertEqual(expected_value, actual_value)

class Test_JsonSerializationContext(unittest.TestCase):
    def test_varuint(self):
        for expected_value in (0, 1, 2**32):
            actual_value = boxed_varuint.json_deserialize({'i':expected_value}).i
            self.assertEqual(expected_value, actual_value)

            actual_json = boxed_varuint(actual_value).json_serialize()
            self.assertEqual({'i':expected_value}, actual_json)