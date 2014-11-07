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
import uuid

from proofmarshal import *
from proofmarshal.test import load_test_vectors, x, b2x

class boxed_varuint(ImmutableProof):
    """Dummy object with a single varuint in it"""

    HASH_HMAC_KEY = x('dd2617248e435da6db7c119c17cc19cd')

    def __init__(self, i):
        object.__setattr__(self, 'i', i)

    def _ctx_serialize(self, ctx):
        ctx.write_varuint('i', self.i)

    def _ctx_deserialize(self, ctx):
        object.__setattr__(self, 'i', ctx.read_varuint('i'))

class boxed_bytes(ImmutableProof):
    """Dummy object with a single bytes attribute"""

    HASH_HMAC_KEY = x('f690a4d282810e868a0d7d59578a6585')
    EXPECTED_LENGTH = None

    def __init__(self, buf):
        object.__setattr__(self, 'buf', buf)

    def _ctx_serialize(self, ctx):
        ctx.write_bytes('buf', self.buf, self.EXPECTED_LENGTH)

    def _ctx_deserialize(self, ctx):
        object.__setattr__(self, 'buf', ctx.read_bytes('buf', self.EXPECTED_LENGTH))

class boxed_objs(ImmutableProof):
    """Object with other objects"""

    HASH_HMAC_KEY = x('296d566c10ebb4b92e8a7f6e909eb191')

    def __init__(self, buf, i):
        object.__setattr__(self, 'buf', boxed_bytes(buf))
        object.__setattr__(self, 'i', boxed_varuint(i))

    def _ctx_serialize(self, ctx):
        ctx.write_obj('buf', self.buf)
        ctx.write_obj('i', self.i)

    def _ctx_deserialize(self, ctx):
        object.__setattr__(self, 'buf', ctx.read_obj('buf', boxed_bytes))
        object.__setattr__(self, 'i', ctx.read_obj('i', boxed_varuint))

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

    def test_bytes(self):
        """Test bytes against vectors"""

        for expected_hex_bytes, expected_hex_value, expected_length in load_test_vectors('valid_bytes.json'):
            expected_bytes = x(expected_hex_bytes)
            expected_value = x(expected_hex_value)

            class our_boxed_bytes(boxed_bytes):
                EXPECTED_LENGTH=expected_length

            # serialize
            actual_bytes = our_boxed_bytes(expected_value).serialize()
            self.assertEqual(b2x(expected_bytes), b2x(actual_bytes))

            # deserialize
            actual_value = our_boxed_bytes.deserialize(expected_bytes).buf
            self.assertEqual(b2x(expected_value), b2x(actual_value))

    def test_objs(self):
        """Test object serialization"""
        for expected_hex_serialized_bytes, expected_hex_buf, expected_i, expected_hex_hash \
                in load_test_vectors('valid_boxed_objs.json'):

            expected_serialized_bytes = x(expected_hex_serialized_bytes)
            expected_buf = x(expected_hex_buf)

            # serialize
            actual_serialized_bytes = boxed_objs(expected_buf, expected_i).serialize()
            self.assertEqual(b2x(expected_serialized_bytes), b2x(actual_serialized_bytes))

            # deserialize
            actual_boxed_obj = boxed_objs.deserialize(expected_serialized_bytes)
            self.assertEqual(b2x(expected_buf), b2x(actual_boxed_obj.buf.buf))
            self.assertEqual(expected_i, actual_boxed_obj.i.i)

            # round-trip
            roundtrip_serialized_bytes = actual_boxed_obj.serialize()
            self.assertEqual(b2x(expected_serialized_bytes), b2x(roundtrip_serialized_bytes))

class Test_JsonSerializationContext(unittest.TestCase):
    def test_varuint(self):
        for expected_value in (0, 1, 2**32):
            actual_value = boxed_varuint.json_deserialize({'i':expected_value}).i
            self.assertEqual(expected_value, actual_value)

            actual_json = boxed_varuint(actual_value).json_serialize()
            self.assertEqual({'i':expected_value}, actual_json)

    def test_bytes(self):
        for expected_json_value, expected_value in (('', b''), ('deadbeef', b'\xde\xad\xbe\xef')):
            actual_value = boxed_bytes.json_deserialize({'buf':expected_json_value}).buf
            self.assertEqual(expected_value, actual_value)

            actual_json = boxed_bytes(actual_value).json_serialize()
            self.assertEqual({'buf':expected_json_value}, actual_json)

class Test_HashSerializationContext(unittest.TestCase):
    def test_objs(self):
        """Test object hashing"""
        for expected_hex_serialized_bytes, expected_hex_buf, expected_i, expected_hex_hash \
                in load_test_vectors('valid_boxed_objs.json'):

            expected_buf = x(expected_hex_buf)
            expected_hash = x(expected_hex_hash)

            actual_hash = boxed_objs(expected_buf, expected_i).hash
            self.assertEqual(b2x(expected_hash), b2x(actual_hash))
