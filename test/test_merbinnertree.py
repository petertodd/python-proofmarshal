# Copyright (C) 2014 Peter Todd <pete@petertodd.org>
#
# This file is part of python-proofmarshal.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-proofmarshal, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import binascii
import hashlib
import json
import os
import struct
import unittest
import uuid

from proofmarshal.test import *

from proofmarshal.merbinnertree import *

class BytesBytesMerbinnerTree(MerbinnerTree):
    HASH_HMAC_KEY = x('92e8898fcfa8b86b60b32236d6990da0')

    KEY_LENGTH = 4
    VALUE_LENGTH = 4

    key_serialize = lambda self, ctx, key: ctx.write_bytes('key', key, self.KEY_LENGTH)
    key_deserialize = lambda self, ctx: ctx.read_bytes('key', self.KEY_LENGTH)

    value_serialize = lambda self, ctx, value: ctx.write_bytes('value', value, self.VALUE_LENGTH)
    value_deserialize = lambda self, ctx: ctx.read_bytes('value', self.VALUE_LENGTH)

    key_gethash = lambda self, key: key
    value_gethash = lambda self, value: value


class Test_MerbinnerTree(unittest.TestCase):
    def test_hash(self):
        """Manual test of the hash calculation"""

        # test-the-test to ensure we understand exactly what is going on

        def h(buf):
             return hmac.HMAC(BytesBytesMerbinnerTree.HASH_HMAC_KEY, buf, hashlib.sha256).digest()

        # "Empty"
        self.assertEqual('ae135d71df652ca291b2025b06165c285aaa0f8ce9609783294d210d371ac8d9',
                        b2x(h(x('00'))))

        # "Leaf"
        self.assertEqual('7b9f6282fa917a0c391bcf96accaad457a40fe31dcd4cdfc17e49dfba311dffb',
                        b2x(h(x('01ffffffffdeadbeef'))))

        # "Inner with left and right leaf children"
        self.assertEqual('65ada255d463e50f569a2ac79a10772d1a3a5262deab2b3ca4bbef466abe8702',
                        b2x(h(x('02') + h(x('01ffffffffdeadbeef')) + h(x('0100000000cafebabe')))))

        # "Inner with collision on first bit"
        self.assertEqual('6d00bce57a2178c209ab6ba3811022d98bd57d8ddc7129f4f9681de6aabc6f71',
                        b2x(h(x('02') +
                              h(x('02') + h(x('01ffffffffdeadbeef')) + h(x('0180000000cafebabe'))) +
                              h(x('00')))))

    def test_vectors(self):
        for json_test_case in load_test_vectors('merbinnertree_hashes.json'):
            items, mode, expected_digest = json_test_case

            items = [(x(k),x(v)) for k,v in items.items()]
            expected_digest = x(expected_digest)

            mbtree = BytesBytesMerbinnerTree(items)

            actual_digest = None
            if mode == 'serialize':
                actual_digest = mbtree.serialize()

                mbtree2 = BytesBytesMerbinnerTree.deserialize(actual_digest)
                self.assertDictEqual(mbtree, mbtree2)

                roundtrip_digest = mbtree2.serialize()
                self.assertEqual(b2x(expected_digest), b2x(roundtrip_digest))

            elif mode == 'hash':
                actual_digest = mbtree.hash

            else:
                assert False and "invalid test: unknown mode"

            self.assertEqual(b2x(expected_digest), b2x(actual_digest))


sum_struct = struct.Struct('>H')
class SummedBytesBytesMerbinnerTree(BytesBytesMerbinnerTree):
    HASH_HMAC_KEY = x('e630f7a3a784d521533772d43c8874c6')

    VALUE_LENGTH = 6

    sum_serialize = lambda self, ctx, sum: ctx.write_bytes('sum', sum_struct.pack(sum), sum_struct.size)
    sum_deserialize = lambda self, ctx, sum: sum_struct.unpack(ctx.read_bytes('sum', sum_struct.size))[0]

    value_getsum = lambda self, value: sum_struct.unpack(value[-2:])[0]

class Test_SummedMerbinnerTree(unittest.TestCase):
    def test_hash(self):
        """Manual test of the hash calculation"""

        # test-the-test to ensure we understand exactly what is going on

        def h(buf):
             return hmac.HMAC(SummedBytesBytesMerbinnerTree.HASH_HMAC_KEY, buf, hashlib.sha256).digest()

        # "Empty"
        self.assertEqual('8e2759711e9d839f9b80e70eae03481d411350ee47ccb96f04590b954679cdfd',
                        b2x(h(x('00'))))

        # "Leaf"
        self.assertEqual('d203a45121c5a1b3cf75931c08ed5a6ff5c7f8b574d1a98df23f99cf1fe6579b',
                        b2x(h(x('01ffffffffdeadbeef0001'))))

        # "Inner with left and right leaf children"
        self.assertEqual('745305cfcf61e12b1c4fc28702f3db47c7166c8684ca47cabdcd90a4379819ff',
                        b2x(h(x('02') + h(x('01ffffffffdeadbeef0001')) + x('0001') +
                                        h(x('0100000000cafebabe0003')) + x('0003'))))

        # "Inner with collision on first bit"
        self.assertEqual('305cf686476881ebd40efb5848df0ad1da2b3bb9043c20d80c2be5fe5ec0f4b0',
                        b2x(h(x('02') +
                              h(x('02') + h(x('01ffffffffdeadbeef0001')) + x('0001') +
                                          h(x('0180000000cafebabe0003')) + x('0003')) +
                              x('0004') +
                              h(x('00')) +
                              x('0000'))))

    def test_vectors(self):
        for json_test_case in load_test_vectors('summed_merbinnertree_hashes.json'):
            items, mode, (expected_digest, expected_sum)= json_test_case

            items = [(x(k),x(v)) for k,v in items.items()]
            expected_digest = x(expected_digest)

            mbtree = SummedBytesBytesMerbinnerTree(items)

            actual_digest = None
            if mode == 'serialize':
                actual_digest = mbtree.serialize()

                mbtree2 = SummedBytesBytesMerbinnerTree.deserialize(actual_digest)
                self.assertDictEqual(mbtree, mbtree2)

                roundtrip_digest = mbtree2.serialize()
                self.assertEqual(b2x(expected_digest), b2x(roundtrip_digest))

            elif mode == 'hash':
                actual_digest = mbtree.hash

            else:
                assert False and "invalid test: unknown mode"

            self.assertEqual(b2x(expected_digest), b2x(actual_digest))
