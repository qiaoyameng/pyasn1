#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.cer import encoder as cer_encoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful


class IterEncodeEqualityTestCase(BaseTestCase):
    codecs = (
        ('ber-def', ber_encoder, {'defMode': True}),
        ('ber-indef', ber_encoder, {'defMode': False}),
        ('cer', cer_encoder, {}),
        ('der', der_encoder, {}),
    )

    def assertStreamMatchesEncode(self, value, **options):
        for codecName, codec, codecOptions in self.codecs:
            callOptions = dict(codecOptions, **options)

            with self.subTest(codec=codecName):
                expected = codec.encode(value, **callOptions)

                chunks = list(codec.iterencode(value, **callOptions))

                for chunk in chunks:
                    assert isinstance(chunk, bytes)

                assert b''.join(chunks) == expected

    def testPrimitiveTypes(self):
        self.assertStreamMatchesEncode(univ.Integer(0))
        self.assertStreamMatchesEncode(univ.Integer(127))
        self.assertStreamMatchesEncode(univ.Integer(-128))
        self.assertStreamMatchesEncode(univ.Integer(2 ** 100))
        self.assertStreamMatchesEncode(univ.Enumerated(5))
        self.assertStreamMatchesEncode(univ.Boolean(0))
        self.assertStreamMatchesEncode(univ.Boolean(1))
        self.assertStreamMatchesEncode(univ.Null(''))
        self.assertStreamMatchesEncode(univ.ObjectIdentifier('1.3.6.1.4'))
        self.assertStreamMatchesEncode(univ.ObjectIdentifier((2, 100, 3)))
        self.assertStreamMatchesEncode(univ.RelativeOID((1, 3, 6)))
        self.assertStreamMatchesEncode(univ.Real(1.5))
        self.assertStreamMatchesEncode(univ.Real((3, 10, -2)))
        self.assertStreamMatchesEncode(univ.Real('inf'))
        self.assertStreamMatchesEncode(univ.BitString((1, 0, 1, 1)))
        self.assertStreamMatchesEncode(univ.OctetString(b'quick brown fox'))
        self.assertStreamMatchesEncode(char.UTF8String('qwe rty'))
        self.assertStreamMatchesEncode(char.PrintableString('qwe rty'))
        self.assertStreamMatchesEncode(useful.GeneralizedTime('20260926120000Z'))
        self.assertStreamMatchesEncode(useful.UTCTime('260926120000Z'))

    def testNestedSequence(self):
        record = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('room', univ.Integer()),
                namedtype.DefaultedNamedType('age', univ.Integer(45)),
                namedtype.NamedType(
                    'address',
                    univ.Sequence(
                        componentType=namedtype.NamedTypes(
                            namedtype.NamedType('street', char.UTF8String()),
                            namedtype.OptionalNamedType('city', char.UTF8String())
                        )
                    )
                )
            )
        )
        record['id'] = 1
        record['age'] = 45
        record['address']['street'] = 'Main'

        self.assertStreamMatchesEncode(record)

    def testSequenceOf(self):
        sequenceOf = univ.SequenceOf(componentType=univ.Integer())
        sequenceOf.extend(range(50))

        self.assertStreamMatchesEncode(sequenceOf)

    def testSetOfSorting(self):
        setOf = univ.SetOf(componentType=univ.OctetString())
        setOf.extend([b'bb', b'a', b'ccc', b'ab'])

        self.assertStreamMatchesEncode(setOf)

    def testSetWithChoice(self):
        choiceType = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('s', univ.OctetString()),
                namedtype.NamedType('b', univ.Boolean())
            )
        )
        setType = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', choiceType)
            )
        )

        blob = univ.Choice(componentType=choiceType.componentType)
        blob.setComponentByName('s', b'zz')

        setValue = setType.clone()
        setValue.setComponentByName('id', 1)
        setValue.setComponentByName('blob', blob)

        self.assertStreamMatchesEncode(setValue)

        blob = univ.Choice(componentType=choiceType.componentType)
        blob.setComponentByName('b', 1)

        setValue = setType.clone()
        setValue.setComponentByName('id', 1)
        setValue.setComponentByName('blob', blob)

        self.assertStreamMatchesEncode(setValue)

    def testExplicitTags(self):
        taggedInteger = univ.Integer(3).subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 4))

        self.assertStreamMatchesEncode(taggedInteger)

        sequenceOf = univ.SequenceOf(componentType=univ.Integer())
        sequenceOf.extend([1, 2])
        taggedSequenceOf = sequenceOf.subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0))

        self.assertStreamMatchesEncode(taggedSequenceOf)

    def testImplicitTags(self):
        taggedInteger = univ.Integer(3).subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 4))

        self.assertStreamMatchesEncode(taggedInteger)

    def testChunkedOctetString(self):
        octetString = univ.OctetString(b'quick brown fox')

        self.assertStreamMatchesEncode(octetString, maxChunkSize=4)

    def testChunkedBitString(self):
        bitString = univ.BitString(binValue='1' * 100)

        self.assertStreamMatchesEncode(bitString, maxChunkSize=4)

    def testLongOctetString(self):
        # exercises CER segmented string encoding
        self.assertStreamMatchesEncode(univ.OctetString(b'\xab' * 2500))

    def testLongBitString(self):
        self.assertStreamMatchesEncode(univ.BitString(binValue='1' * 10000))

    def testLongCharacterString(self):
        self.assertStreamMatchesEncode(char.UTF8String('x' * 2500))

    def testChoice(self):
        choice = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.OctetString())
            )
        )
        choice.setComponentByName('a', 5)

        self.assertStreamMatchesEncode(choice)

    def testAny(self):
        blob = univ.Any(ber_encoder.encode(univ.Integer(7)))

        self.assertStreamMatchesEncode(blob)

    def testEmptyContainers(self):
        self.assertStreamMatchesEncode(
            univ.SequenceOf(componentType=univ.Integer()))
        self.assertStreamMatchesEncode(
            univ.SetOf(componentType=univ.Integer()))

    def testEmptyOptionalComponent(self):
        record = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType(
                    'items', univ.SequenceOf(componentType=univ.Integer()))
            )
        )
        record['id'] = 1
        record.setComponentByName(
            'items', univ.SequenceOf(componentType=univ.Integer()))

        self.assertStreamMatchesEncode(record)

    def testIfNotEmptyOption(self):
        self.assertStreamMatchesEncode(
            univ.SequenceOf(componentType=univ.Integer()), ifNotEmpty=True)

    def testSchemaGuidedEncoding(self):
        spec = univ.SequenceOf(componentType=univ.Integer())

        self.assertStreamMatchesEncode([1, 2, 3], asn1Spec=spec)

        recordSpec = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('name', char.UTF8String())
            )
        )

        self.assertStreamMatchesEncode(
            {'id': 1, 'name': 'abc'}, asn1Spec=recordSpec)

    def testOpenTypes(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        spec = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.Any(), openType=openType)
            )
        )

        value = spec.clone()
        value[0] = 1
        value[1] = univ.Integer(12)

        self.assertStreamMatchesEncode(value, asn1Spec=value)

        value = spec.clone()
        value[0] = 2
        value[1] = univ.OctetString(b'quick brown')

        self.assertStreamMatchesEncode(value, asn1Spec=value)

    def testSetOfOpenTypes(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        spec = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.SetOf(componentType=univ.Any()),
                    openType=openType)
            )
        )

        value = spec.clone()
        value[0] = 1
        value[1].append(univ.Integer(12))

        self.assertStreamMatchesEncode(value, asn1Spec=value)


class CountingSequenceOf(univ.SequenceOf):
    iterationCount = 0
    componentAccessCount = 0

    @classmethod
    def reset(cls):
        cls.iterationCount = 0
        cls.componentAccessCount = 0

    def __iter__(self):
        CountingSequenceOf.iterationCount += 1
        for component in univ.SequenceOf.__iter__(self):
            CountingSequenceOf.componentAccessCount += 1
            yield component


class CountingInteger(univ.Integer):
    accessCount = 0

    def __int__(self):
        CountingInteger.accessCount += 1
        return univ.Integer.__int__(self)


class CountingOctetString(univ.OctetString):
    sliceCount = 0

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            CountingOctetString.sliceCount += 1
        return univ.OctetString.__getitem__(self, idx)


class IterEncodeLazinessTestCase(BaseTestCase):
    def testBerIndefiniteLengthStreamsComponents(self):
        CountingSequenceOf.reset()
        sequenceOf = CountingSequenceOf(componentType=univ.Integer())
        sequenceOf.extend(range(100))

        iterator = ber_encoder.iterencode(sequenceOf, defMode=False)

        # the debug hook stringifies the value at dispatch time; the
        # streaming property is measured from this point on
        CountingSequenceOf.reset()

        header = next(iterator)
        assert header == bytes((0x30, 0x80))
        # no component has been traversed to produce the header
        assert CountingSequenceOf.componentAccessCount == 0

        firstComponent = next(iterator) + next(iterator)
        assert firstComponent == ber_encoder.encode(univ.Integer(0))
        assert CountingSequenceOf.componentAccessCount == 1

        # caller stops early: the rest of the value is never traversed
        iterator.close()
        assert CountingSequenceOf.componentAccessCount == 1

    def testBerDefiniteLengthConcatEqualsEncode(self):
        CountingSequenceOf.reset()
        sequenceOf = CountingSequenceOf(componentType=univ.Integer())
        sequenceOf.extend(range(100))

        chunks = list(ber_encoder.iterencode(sequenceOf, defMode=True))

        assert b''.join(chunks) == ber_encoder.encode(
            sequenceOf, defMode=True)

    def testCerSegmentedStringStreamsChunks(self):
        CountingOctetString.sliceCount = 0
        octetString = CountingOctetString(b'\x01' * 2500)

        iterator = cer_encoder.iterencode(octetString)

        header = next(iterator)
        assert header == bytes((0x24, 0x80))
        # no segment has been cut out of the value to produce the header
        assert CountingOctetString.sliceCount == 0

        segmentHeader = next(iterator)
        assert segmentHeader == bytes((0x04, 0x82, 0x03, 0xe8))
        assert CountingOctetString.sliceCount == 1

        segmentPayload = next(iterator)
        assert segmentPayload == b'\x01' * 1000
        assert CountingOctetString.sliceCount == 1

        # caller stops early: the remaining segments are never cut
        iterator.close()
        assert CountingOctetString.sliceCount == 1

    def testDerEncodesComponentsAfterLengthComputation(self):
        sequenceOf = univ.SequenceOf(componentType=CountingInteger())
        sequenceOf.extend(range(1, 101))
        CountingInteger.accessCount = 0

        iterator = der_encoder.iterencode(sequenceOf)

        header = next(iterator)
        # definite-length framing precomputes the content length, which
        # touches every component once...
        assert CountingInteger.accessCount == 100

        next(iterator)
        next(iterator)
        # ...but the values themselves are encoded lazily, one at a time
        assert CountingInteger.accessCount == 102

        # caller stops early: the remaining components are never encoded
        iterator.close()
        assert CountingInteger.accessCount == 102

    def testDerDoesNotMaterializeEncodedCopy(self):
        payload = b'\x01' * 100000
        octetString = univ.OctetString(payload)

        for codec, options in ((ber_encoder, {'defMode': True}),
                               (der_encoder, {})):
            with self.subTest(codec=codec):
                chunks = list(codec.iterencode(octetString, **options))

                assert b''.join(chunks) == codec.encode(octetString, **options)

                # the payload chunk is the original octets object
                # itself: no copy of the encoded value was made
                assert any(chunk is payload for chunk in chunks)


class IterEncodeErrorHandlingTestCase(BaseTestCase):
    def testNonAsn1ValueRejected(self):
        for codec in (ber_encoder, cer_encoder, der_encoder):
            with self.subTest(codec=codec):
                try:
                    list(codec.iterencode(object()))
                except PyAsn1Error:
                    pass
                else:
                    assert 0, 'iterencode() tolerated non-ASN.1 value'

    def testEncodingErrorPropagatesThroughIteration(self):
        sequenceOf = univ.SequenceOf(componentType=univ.ObjectIdentifier())
        sequenceOf.append(univ.ObjectIdentifier('1.3'))
        sequenceOf.append(univ.ObjectIdentifier(()))

        for codec, options in ((ber_encoder, {}),
                               (ber_encoder, {'defMode': False}),
                               (der_encoder, {})):
            with self.subTest(codec=codec, options=options):
                try:
                    list(codec.iterencode(sequenceOf, **options))
                except PyAsn1Error:
                    pass
                else:
                    assert 0, 'iterencode() tolerated short OID'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
