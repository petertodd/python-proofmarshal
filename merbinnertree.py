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

import operator

def calc_summed_merbinner_hash(items, *,
                               hash_func=None,
                               sum_serialize_func=None,
                               sum_func=operator.add,
                               empty_sum=0,
                               _depth=0):
    """Calculate a summed merbinner tree hash over an iterable of (H(key), H(value), sum) tuples

    hash_func          - Hash function to use
    sum_serialize_func - Function that takes a sum and serializes it to bytes
    sum_func           - Function to sum sums together (default: operator.add)
    empty_sum          - Value of an empty node (default: 0)

    Returns (hash, sum)
    """
    items = tuple(items) # FIXME: could do this more efficiently

    if len(items) == 0:
        # Empty node
        return (hash_func(b'\x00'), empty_sum)

    elif len(items) == 1:
        # Leaf node

        k, v, s = items[0]
        return (hash_func(b'\x01' + k + v + sum_serialize_func(s)), s)

    else:
        # Inner node

        # Sort pairs into left and right sides
        left_items = []
        right_items = []
        for key, value, s in items:
            # FIXME: detect dup keys here
            side = key[_depth // 8] >> (7 - _depth % 8) & 0b1
            if side:
                left_items.append((key, value, s))

            else:
                right_items.append((key, value, s))

        (left_hash,  left_sum)  = calc_summed_merbinner_hash(left_items,
                                                             hash_func=hash_func, sum_serialize_func=sum_serialize_func,
                                                             sum_func=sum_func, empty_sum=empty_sum,
                                                             _depth=_depth+1)
        (right_hash, right_sum) = calc_summed_merbinner_hash(right_items,
                                                             hash_func=hash_func, sum_serialize_func=sum_serialize_func,
                                                             sum_func=sum_func, empty_sum=empty_sum,
                                                             _depth=_depth+1)

        return (hash_func(b'\x02' + left_hash + sum_serialize_func(left_sum) + right_hash + sum_serialize_func(right_sum)),
                sum_func(left_sum, right_sum))

def calc_merbinner_hash(items, *, hash_func=None, _depth=0):
    """Calculate a merbinner tree hash over an iterable of (H(key), H(value)) pairs

    hash_func - Hash function to use

    Returns hash
    """
    return calc_summed_merbinner_hash(((k, v, 0) for k,v in items),
                                      hash_func=hash_func,
                                      sum_serialize_func=lambda s: b'')[0]
