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

import hashlib
import hmac
import operator

import proofmarshal

class MerbinnerTree(proofmarshal.ImmutableProof, dict):
    """Temporary non-prunable merbinner tree

    To reduce implementation effort for the Java team.
    """
    HASH_HMAC_KEY = None

    SUM_IDENTITY = 0

    key_serialize = None
    key_deserialize = None
    value_serialize = None
    value_deserialize = None
    sum_serialize = lambda self, ctx, sum: None
    sum_deserialize = lambda self, ctx, sum: 0

    key_gethash = lambda self, key: key.hash
    value_gethash = lambda self, value: value.hash
    value_getsum = lambda self, value: 0

    sum_func = operator.add

    def _ctx_serialize(self, ctx):
        def recurse(ctx, items, depth):
            if len(items) == 0:
                # Empty node
                ctx.write_varuint('type', 0)
                return self.SUM_IDENTITY

            elif len(items) == 1:
                # Leaf node
                ctx.write_varuint('type', 1)

                key, value, sum = items[0]
                self.key_serialize(ctx, key)
                self.value_serialize(ctx, value)

                return sum

            else:
                # Inner node
                ctx.write_varuint('type', 2)

                # Sort items into left and right sides
                left_items = []
                right_items = []
                for key, value, sum in items:
                    # FIXME: detect dup keys here
                    keyhash = self.key_gethash(key)
                    side = key[depth // 8] >> (7 - depth % 8) & 0b1

                    if side:
                        left_items.append((key, value, sum))
                    else:
                        right_items.append((key, value, sum))

                # Definitely a hack, but if we're hashing, rather than
                # serializing, we need to create new contexts and do the hmac
                # hash calculation. This hack will get removed when the full
                # prunable merbinner tree is implemented.
                def do_recurse(items):
                    sum = None
                    if isinstance(ctx, proofmarshal.HashSerializationContext):
                        next_ctx = proofmarshal.HashSerializationContext()
                        sum = recurse(next_ctx, items, depth+1)
                        hash = hmac.HMAC(self.HASH_HMAC_KEY, next_ctx.getbytes(), hashlib.sha256).digest()
                        ctx.write_bytes(None, hash, 32)

                        # Also, sum only needs to be serialized while hashing;
                        # serializing it otherwise is redundent as the sums can
                        # be recalculated from the values. (future pruned nodes
                        # will have a sum field)
                        self.sum_serialize(ctx, sum)
                    else:
                        sum = recurse(ctx, items, depth+1)

                    return sum

                left_sum = do_recurse(left_items)
                right_sum = do_recurse(right_items)

                return self.sum_func(left_sum, right_sum)

        items = [(key, value, self.value_getsum(value)) for key, value in self.items()]

        final_sum = recurse(ctx, items, 0)

    def _ctx_deserialize(self, ctx):
        items = {}
        def recurse():
            node_type = ctx.read_varuint('type')

            if node_type == 0:
                # Empty node, do nothing
                pass

            elif node_type == 1:
                # Leaf node
                key = self.key_deserialize(ctx)
                value = self.value_deserialize(ctx)

                self[key] = value

            elif node_type == 2:
                # Inner node
                recurse() # left
                recurse() # right

            else:
                raise Exception('unsupported node type: %d' % node_type)

        recurse()
