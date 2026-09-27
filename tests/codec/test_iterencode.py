#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import tag
from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.type import char
from pyasn1.type import useful
from pyasn1 import debug
from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.cer import encoder as cer_encoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.ber import eoo
from pyasn1.error import PyAsn1Error


class CountingSequenceOf(univ.SequenceOf):
    """SequenceOf counting how many components get pulled out of it"""

    iterated = 0

    def __iter__(self):
        for component in univ.SequenceOf.__iter__(self):
            type(self).iterated += 1
            yield component


class CountingOctetString(univ.OctetString):
    """OctetString counting how many times it gets sliced"""

    slices = 0

    def __getitem__(self, idx):
        type(self).slices += 1
        return univ.OctetString.__getitem__(self, idx)


class BerIterEncoderTestCase(BaseTestCase):
    def testScalar(self):
        assert b''.join(
            ber_encoder.iterencode(univ.Integer(12))) == bytes((2, 1, 12))

    def testScalarIndefMode(self):
        # primitives still get definite length in indefinite mode
        assert b''.join(ber_encoder.iterencode(
            univ.Integer(12), defMode=False)) == bytes((2, 1, 12))

    def testSequenceOf(self):
        s = univ.SequenceOf(componentType=univ.Integer())
        s.extend([1, 2, 3])
        assert b''.join(ber_encoder.iterencode(s)) == ber_encoder.encode(s)

    def testSequenceOfIndefMode(self):
        s = univ.SequenceOf(componentType=univ.Integer())
        s.extend([1, 2, 3])
        substrate = b''.join(ber_encoder.iterencode(s, defMode=False))
        assert substrate == ber_encoder.encode(s, defMode=False)
        assert substrate == bytes((48, 128, 2, 1, 1, 2, 1, 2, 2, 1, 3, 0, 0))

    def testNestedSequenceOfIndefMode(self):
        inner = univ.SequenceOf(componentType=univ.OctetString())
        inner.extend(['aa', 'bb'])
        outer = univ.SequenceOf(
            componentType=univ.SequenceOf(
                componentType=univ.OctetString()))
        outer.extend([inner, inner])
        substrate = b''.join(ber_encoder.iterencode(outer, defMode=False))
        assert substrate == ber_encoder.encode(outer, defMode=False)

    def testExplicitTagIndefMode(self):
        s = univ.Integer(5).subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 3))
        substrate = b''.join(ber_encoder.iterencode(s, defMode=False))
        assert substrate == ber_encoder.encode(s, defMode=False)
        assert substrate == bytes((163, 3, 2, 1, 5, 0, 0))

    def testDoubleExplicitTagIndefMode(self):
        s = univ.Integer(5).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
        ).subtype(
            explicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 7)
        )
        substrate = b''.join(ber_encoder.iterencode(s, defMode=False))
        assert substrate == ber_encoder.encode(s, defMode=False)

    def testExplicitTagDefMode(self):
        s = univ.Integer(5).subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 3))
        substrate = b''.join(ber_encoder.iterencode(s))
        assert substrate == ber_encoder.encode(s)
        assert substrate == bytes((163, 3, 2, 1, 5))

    def testChunkedOctetStringIndefMode(self):
        s = univ.OctetString(bytes(range(256)) * 8)
        substrate = b''.join(ber_encoder.iterencode(
            s, defMode=False, maxChunkSize=100))
        assert substrate == ber_encoder.encode(
            s, defMode=False, maxChunkSize=100)

    def testChunkedBitStringIndefMode(self):
        s = univ.BitString((1,) * 333)
        substrate = b''.join(ber_encoder.iterencode(
            s, defMode=False, maxChunkSize=10))
        assert substrate == ber_encoder.encode(
            s, defMode=False, maxChunkSize=10)

    def testSequenceWithSchema(self):
        class Rec(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('name', char.UTF8String()),
                namedtype.DefaultedNamedType('flag', univ.Boolean(1))
            )

        r = Rec()
        r['id'] = 42
        r['name'] = 'x'
        r['flag'] = 0

        assert b''.join(ber_encoder.iterencode(r)) == ber_encoder.encode(r)
        assert b''.join(ber_encoder.iterencode(
            r, defMode=False)) == ber_encoder.encode(r, defMode=False)

    def testBareValueWithSchema(self):
        s = univ.SequenceOf(componentType=univ.Integer())
        assert b''.join(ber_encoder.iterencode(
            [1, 2, 3], asn1Spec=s)) == ber_encoder.encode([1, 2, 3], asn1Spec=s)

    def testChoice(self):
        c = univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('x', univ.Integer()),
            namedtype.NamedType('y', univ.OctetString())
        ))
        c['x'] = 3
        assert b''.join(ber_encoder.iterencode(c)) == ber_encoder.encode(c)
        assert b''.join(ber_encoder.iterencode(
            c, defMode=False)) == ber_encoder.encode(c, defMode=False)

    def testEndOfOctets(self):
        assert b''.join(
            ber_encoder.iterencode(eoo.endOfOctets)) == bytes((0, 0))

    def testEncoderInstanceMethod(self):
        s = univ.SequenceOf(componentType=univ.Integer())
        s.extend([1, 2, 3])
        enc = ber_encoder.Encoder()
        assert b''.join(enc.iterencode(s)) == enc(s)


class BerIterEncoderStreamingTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        # debug logging eagerly stringifies the value being encoded,
        # which traverses it -- keep it off to observe lazy traversal
        debug.setLogger(None)

        CountingSequenceOf.iterated = 0
        CountingOctetString.slices = 0

    def testNoWorkBeforeIteration(self):
        s = CountingSequenceOf(componentType=univ.Integer())
        s.extend(range(100))

        ber_encoder.iterencode(s, defMode=False)

        assert CountingSequenceOf.iterated == 0

    def testIndefModeIsLazy(self):
        s = CountingSequenceOf(componentType=univ.Integer())
        s.extend(range(100))

        chunks = ber_encoder.iterencode(s, defMode=False)

        assert next(chunks) == bytes((48, 128))
        assert CountingSequenceOf.iterated == 0

        next(chunks)
        assert CountingSequenceOf.iterated <= 1

    def testEarlyStopSkipsRemainingComponents(self):
        s = CountingSequenceOf(componentType=univ.Integer())
        s.extend(range(100))

        chunks = ber_encoder.iterencode(s, defMode=False)

        next(chunks)
        next(chunks)
        chunks.close()

        assert CountingSequenceOf.iterated <= 1

    def testChunkedOctetStringIsLazy(self):
        s = CountingOctetString(b'x' * 10000)

        chunks = ber_encoder.iterencode(s, defMode=False, maxChunkSize=1000)

        assert next(chunks) == bytes((36, 128))
        next(chunks)

        assert CountingOctetString.slices <= 1

    def testDefModeMeasuresWithoutKeepingSubstrate(self):
        s = CountingSequenceOf(componentType=univ.Integer())
        s.extend(range(100))

        substrate = ber_encoder.encode(s)

        CountingSequenceOf.iterated = 0

        chunks = list(ber_encoder.iterencode(s))

        assert b''.join(chunks) == substrate

        # definite length needs a measuring pass plus an encoding pass,
        # never a full extra traversal on top of that
        assert CountingSequenceOf.iterated == 2 * len(s)

        # the substrate comes out in pieces, not as one blob
        assert len(chunks) > 1
        assert max(map(len, chunks)) < len(substrate)


class CerIterEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        debug.setLogger(None)
        CountingSequenceOf.iterated = 0
        CountingOctetString.slices = 0

    def testSequenceOf(self):
        s = univ.SequenceOf(componentType=univ.Integer())
        s.extend([1, 2, 3])
        substrate = b''.join(cer_encoder.iterencode(s))
        assert substrate == cer_encoder.encode(s)
        assert substrate == bytes((48, 128, 2, 1, 1, 2, 1, 2, 2, 1, 3, 0, 0))

    def testSetOfSorting(self):
        s = univ.SetOf(componentType=univ.OctetString())
        s.extend(['xy', 'def', 'a', 'bc'])
        assert b''.join(cer_encoder.iterencode(s)) == cer_encoder.encode(s)

    def testSetSorting(self):
        class S(univ.Set):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('b', univ.Boolean()),
                namedtype.NamedType('i', univ.Integer())
            )

        s = S()
        s['i'] = 7
        s['b'] = 1

        assert b''.join(cer_encoder.iterencode(s)) == cer_encoder.encode(s)

    def testSegmentedOctetString(self):
        s = univ.OctetString(b'x' * 4500)
        substrate = b''.join(cer_encoder.iterencode(s))
        assert substrate == cer_encoder.encode(s)
        # CER segments long strings into 1000-octet chunks
        assert substrate[:4] == bytes((36, 128, 4, 130))

    def testSegmentedOctetStringIsLazy(self):
        s = CountingOctetString(b'x' * 10000)

        chunks = cer_encoder.iterencode(s)

        assert next(chunks) == bytes((36, 128))
        next(chunks)

        assert CountingOctetString.slices <= 1

    def testEarlyStopSkipsRemainingComponents(self):
        s = CountingSequenceOf(componentType=univ.Integer())
        s.extend(range(100))

        chunks = cer_encoder.iterencode(s)

        next(chunks)
        next(chunks)
        chunks.close()

        assert CountingSequenceOf.iterated <= 1

    def testGeneralizedTime(self):
        s = useful.GeneralizedTime('20260928120000Z')
        assert b''.join(cer_encoder.iterencode(s)) == cer_encoder.encode(s)


class DerIterEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        debug.setLogger(None)
        CountingSequenceOf.iterated = 0

    def testSequenceOf(self):
        s = univ.SequenceOf(componentType=univ.Integer())
        s.extend([1, 2, 3])
        assert b''.join(
            der_encoder.iterencode(s)) == bytes((48, 9, 2, 1, 1, 2, 1, 2, 2, 1, 3))

    def testNestedSequence(self):
        class Rec(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('name', char.UTF8String())
            )

        r = Rec()
        r['id'] = 42
        r['name'] = 'x'

        assert b''.join(der_encoder.iterencode(r)) == der_encoder.encode(r)

    def testSetSorting(self):
        class S(univ.Set):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('b', univ.Boolean()),
                namedtype.NamedType('i', univ.Integer())
            )

        s = S()
        s['i'] = 7
        s['b'] = 1

        assert b''.join(der_encoder.iterencode(s)) == der_encoder.encode(s)

    def testSetOfSorting(self):
        s = univ.SetOf(componentType=univ.OctetString())
        s.extend(['xy', 'def', 'a', 'bc'])
        assert b''.join(der_encoder.iterencode(s)) == der_encoder.encode(s)

    def testExplicitTag(self):
        s = univ.Integer(5).subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 3))
        assert b''.join(
            der_encoder.iterencode(s)) == bytes((163, 3, 2, 1, 5))

    def testDefiniteLengthNeedsTwoPassesOnly(self):
        s = CountingSequenceOf(componentType=univ.Integer())
        s.extend(range(100))

        substrate = der_encoder.encode(s)

        CountingSequenceOf.iterated = 0

        assert b''.join(der_encoder.iterencode(s)) == substrate

        # one pass to measure the content length, one to encode it --
        # a hidden full pre-encoding would not need the second pass
        assert CountingSequenceOf.iterated == 2 * len(s)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
