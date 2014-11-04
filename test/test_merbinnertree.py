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

from proofmarshal.merbinnertree import *

def x(h):
    h = h.replace(' ','')
    return binascii.unhexlify(h.encode('utf8'))

def b2x(b):
    return binascii.hexlify(b).decode('utf8')

def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for test_case in json.load(fd):
            yield test_case

class Test_calc_merbinner_hash(unittest.TestCase):
    def test_vectors(self):
        for json_test_case in load_test_vectors('merbinnertree_hashes.json'):
            if len(json_test_case) == 1:
                # comment, ignore
                continue

            elif len(json_test_case) == 3:
                items, hash_func, expected_digest = json_test_case

                items = [(x(k),x(v)) for k,v in items.items()]
                expected_digest = x(expected_digest)

                if hash_func == 'cat':
                    hash_func = lambda msg: msg

                elif hash_func == 'sha256':
                    hash_func = lambda msg: hashlib.sha256(msg).digest()

                else:
                    assert False and "invalid test: unknown hash function"

                actual_digest = calc_merbinner_hash(items, hash_func=hash_func)

                self.assertEqual(b2x(expected_digest), b2x(actual_digest))

            else:
                assert False and "invalid test: malformed"

class Test_calc_summed_merbinner_hash(unittest.TestCase):
    def test_vectors(self):
        packer = struct.Struct('>H')
        sum_serialize_func = lambda s: packer.pack(s)

        for json_test_case in load_test_vectors('summed_merbinnertree_hashes.json'):
            if len(json_test_case) == 1:
                # comment, ignore
                continue

            elif len(json_test_case) == 3:
                items, hash_func, (expected_digest, expected_sum)= json_test_case

                items = [(x(k),x(v),s) for k,(v,s) in items.items()]
                expected_digest = x(expected_digest)

                if hash_func == 'cat':
                    hash_func = lambda msg: msg

                elif hash_func == 'sha256':
                    hash_func = lambda msg: hashlib.sha256(msg).digest()

                else:
                    assert False and "invalid test: unknown hash function"

                (actual_digest, actual_sum) = calc_summed_merbinner_hash(items,
                                                                         hash_func=hash_func,
                                                                         sum_serialize_func=sum_serialize_func)

                self.assertEqual(b2x(expected_digest), b2x(actual_digest))
                self.assertEqual(expected_sum, actual_sum)

            else:
                assert False and "invalid test: malformed"
