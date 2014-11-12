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
import hmac
import io

"""Cryptographic proof marshalling

Provides serialization and deserialization for complex, immutable,
cryptographic proofs.
"""

class SerializationContext:
    """Context for serialization

    Allows multiple serialization targets to share the same codebase, for
    instance bytes, memoized serialization, hashing, JSON, etc.
    """

    def write_varuint(self, attr_name, value):
        """Write a variable-length unsigned integer"""
        raise NotImplementedError

    def write_bytes(self, attr_name, value, expected_length=None):
        """Write a variable-length byte array"""
        raise NotImplementedError

    def write_obj(self, attr_name, value, serialization_class=None):
        raise NotImplementedError

class DeserializationContext:
    """Context for deserialization

    Allows multiple deserialization sources to share the same codebase, for
    instance bytes, memoized serialization, hashing, JSON, etc.
    """

    def read_varuint(self, attr_name, value):
        """Write a variable-length unsigned integer"""
        raise NotImplementedError

    def read_bytes(self, attr_name, expected_length=None):
        """Read a variable-length byte array"""
        raise NotImplementedError

    def read_obj(self, attr_name, serialization_class=None):
        raise NotImplementedError

class StreamSerializationContext(SerializationContext):
    def __init__(self, fd):
        self.fd = fd

    def write_varuint(self, attr_name, value):
        # unsigned little-endian base128 format (LEB128)
        if value == 0:
            self.fd.write(b'\x00')

        else:
            while value != 0:
                b = value & 0b01111111
                if value > 0b01111111:
                    b |= 0b10000000
                self.fd.write(bytes([b]))
                if value <= 0b01111111:
                    break
                value >>= 7

    def write_bytes(self, attr_name, value, expected_length=None):
        if expected_length is None:
            self.write_varuint(None, len(value))
        else:
            # FIXME: proper exception
            assert len(value) == expected_length
        self.fd.write(value)

    def write_obj(self, attr_name, value, serialization_class=None):
        assert serialization_class is None
        value.ctx_serialize(self)

class StreamDeserializationContext(DeserializationContext):
    def __init__(self, fd):
        self.fd = fd

    def fd_read(self, l):
        r = self.fd.read(l)
        assert len(r) == l # FIXME: raise exception
        return r

    def read_varuint(self, attr_name):
        value = 0
        shift = 0

        while True:
            b = self.fd_read(1)[0]
            value |= (b & 0b01111111) << shift
            if not (b & 0b10000000):
                break
            shift += 7

        return value

    def read_bytes(self, attr_name, expected_length=None):
        if expected_length is None:
            expected_length = self.read_varuint(None)
        return self.fd_read(expected_length)

    def read_obj(self, attr_name, serialization_class):
        return serialization_class.ctx_deserialize(self)

class BytesSerializationContext(StreamSerializationContext):
    def __init__(self):
        super().__init__(io.BytesIO())

    def getbytes(self):
        """Return the bytes serialized to date"""
        return self.fd.getvalue()

class BytesDeserializationContext(StreamDeserializationContext):
    def __init__(self, buf):
        super().__init__(io.BytesIO(buf))

    # FIXME: need to check that there isn't extra crap at end of object


class JsonSerializationContext:
    """serialize to a human-readable JSON-compatible dict"""

    def __init__(self):
        self.pairs = {}

    def write_varuint(self, attr_name, value):
        assert attr_name not in self.pairs
        self.pairs[attr_name] = value

    def write_bytes(self, attr_name, value, expected_length=None):
        assert attr_name not in self.pairs
        hex_value = binascii.hexlify(value).decode('utf8')
        self.pairs[attr_name] = hex_value


class JsonDeserializationContext:
    """deserialize a human-readable JSON-compatible attribute-value pairs"""

    def __init__(self, pairs=None):
        self.pairs = pairs

    def read_varuint(self, attr_name):
        return self.pairs[attr_name]

    def read_bytes(self, attr_name, expected_length):
        return binascii.unhexlify(self.pairs[attr_name].encode('utf8'))

class HashSerializationContext(BytesSerializationContext):
    """Serialization context for calculating hashes of objects

    Serialization is never recursive in this context; when encountering an
    object its hash is used instead.
    """

    def write_bytes(self, attr_name, value, expected_length=None):
        # FIXME: should we write the bytes themselves, or the hash of the bytes?
        if expected_length is None:
            self.write_varuint(None, len(value))
        else:
            # FIXME: proper exception
            assert len(value) == expected_length
        self.fd.write(value)

    def write_obj(self, attr_name, value, serialization_class=None):
        hash = None
        if serialization_class is None:
            hash = value.hash

        else:
            hash = serialization_class.calc_hash(value)

        assert len(hash) == 32
        self.write_bytes(None, hash, 32)

class Serializer:
    """Serializes an instance of a class"""

    HASH_HMAC_KEY = None

    @classmethod
    def ctx_serialize(cls, self, ctx):
        """Serialize to a serialization context"""
        raise NotImplementedError

    @classmethod
    def ctx_deserialize(cls, ctx):
        """Deserialize from a serialization context"""
        raise NotImplementedError

    @classmethod
    def serialize(cls, self):
        """Serialize to bytes"""
        ctx = BytesSerializationContext()
        self.ctx_serialize(ctx)
        return ctx.getbytes()

    @classmethod
    def stream_deserialize(cls, fd):
        """Deserialize from a stream"""
        ctx = StreamDeserializationContext(fd)
        return cls.ctx_deserialize(ctx)

    @classmethod
    def stream_serialize(cls, self, fd):
        """Serialize to a stream"""
        ctx = StreamSerializationContext(fd)
        self.ctx_serialize(ctx)

    @classmethod
    def deserialize(cls, buf):
        """Deserialize from bytes"""
        ctx = BytesDeserializationContext(buf)
        return cls.ctx_deserialize(ctx)

    @classmethod
    def json_serialize(cls, self):
        """Serialize to JSON-compatible attribute-value pairs"""
        ctx = JsonSerializationContext()
        self.ctx_serialize(ctx)
        return ctx.pairs

    @classmethod
    def json_deserialize(cls, pairs):
        """Serialize from JSON-compatible attribute-value pairs"""
        ctx = JsonDeserializationContext(pairs)
        return cls.ctx_deserialize(ctx)

    @classmethod
    def calc_hash(cls, self):
        ctx = HashSerializationContext()
        cls.ctx_serialize(self, ctx)
        return hmac.HMAC(cls.HASH_HMAC_KEY, ctx.getbytes(), hashlib.sha256).digest()

class ImmutableProof:
    """Base class for immutable proof objects


    """
    __slots__ = []

    HASH_HMAC_KEY = None

    def __setattr__(self, name, value):
        raise AttributeError('Object is immutable')

    def __delattr__(self, name):
        raise AttributeError('Object is immutable')

    def ctx_serialize(self, ctx):
        return self._ctx_serialize(ctx)

    @classmethod
    def ctx_deserialize(cls, ctx):
        self = cls.__new__(cls)
        self._ctx_deserialize(ctx)
        return self

    def serialize(self):
        """Serialize to bytes"""
        ctx = BytesSerializationContext()
        self.ctx_serialize(ctx)
        return ctx.getbytes()

    @classmethod
    def stream_deserialize(cls, fd):
        """Deserialize from a stream"""
        ctx = StreamDeserializationContext(fd)
        return cls.ctx_deserialize(ctx)

    def stream_serialize(self, fd):
        """Serialize to a stream"""
        ctx = StreamSerializationContext(fd)
        self.ctx_serialize(ctx)

    @classmethod
    def deserialize(cls, buf):
        """Deserialize from bytes"""
        ctx = BytesDeserializationContext(buf)
        return cls.ctx_deserialize(ctx)

    def json_serialize(self):
        """Serialize to JSON-compatible attribute-value pairs"""
        ctx = JsonSerializationContext()
        self.ctx_serialize(ctx)
        return ctx.pairs

    @classmethod
    def json_deserialize(cls, pairs):
        """Serialize from JSON-compatible attribute-value pairs"""
        ctx = JsonDeserializationContext(pairs)
        return cls.ctx_deserialize(ctx)

    def calc_hash(self):
        ctx = HashSerializationContext()
        self.ctx_serialize(ctx)
        return hmac.HMAC(self.HASH_HMAC_KEY, ctx.getbytes(), hashlib.sha256).digest()

    @property
    def hash(self):
        try:
            return self._cached_hash
        except AttributeError:
            object.__setattr__(self, '_cached_hash', self.calc_hash())
            return self._cached_hash
