#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import univ
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError


class BitStringDecoderTestCase(BaseTestCase):
    def testShortMode(self):
        assert decoder.decode(
            bytes((3, 127, 6) + (170,) * 125 + (128,))
        ) == (((1, 0) * 501), b'')

    def testIndefMode(self):
        try:
            decoder.decode(
                bytes((35, 128, 3, 2, 0, 169, 3, 2, 1, 138, 0, 0))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'indefinite length encoding tolerated'

    def testDefModeChunked(self):
        try:
            assert decoder.decode(
                bytes((35, 8, 3, 2, 0, 169, 3, 2, 1, 138))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'chunked encoding tolerated'


class OctetStringDecoderTestCase(BaseTestCase):
    def testShortMode(self):
        assert decoder.decode(
            '\004\017Quick brown fox'.encode()
        ) == ('Quick brown fox'.encode(), ''.encode())

    def testIndefMode(self):
        try:
            decoder.decode(
                bytes((36, 128, 4, 15, 81, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111, 120, 0, 0))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'indefinite length encoding tolerated'

    def testChunkedMode(self):
        try:
            decoder.decode(
                bytes((36, 23, 4, 2, 81, 117, 4, 2, 105, 99, 4, 2, 107, 32, 4, 2, 98, 114, 4, 2, 111, 119, 4, 1, 110))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'chunked encoding tolerated'


class LargeTagDecoderTestCase(BaseTestCase):
    def testExcessiveLongTag(self):
        # 1 << 140 is the smallest tag ID needing 21 octets, one over the limit
        excessiveTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1 << 140)
        asn1Spec = univ.Integer().subtype(implicitTag=excessiveTag)
        substrate = encoder.encode(univ.Integer(1).subtype(implicitTag=excessiveTag))

        try:
            decoder.decode(substrate, asn1Spec=asn1Spec)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'excessive long tag tolerated'


class RealDecoderTestCase(BaseTestCase):
    def testCanonicalLargeBinaryReal(self):
        substrate = encoder.encode(univ.Real((1, 2, 1000000)))
        assert substrate == bytes((9, 5, 0x82, 0x0f, 0x42, 0x40, 1))

        value, rest = decoder.decode(substrate)

        assert tuple(value) == (1, 2, 1000000)
        assert rest == b''

    def testLargeBinaryRoundTrip(self):
        substrate = encoder.encode(univ.Real((-1, 2, 76354972)))
        value, rest = decoder.decode(substrate)

        assert tuple(value) == (-1, 2, 76354972)
        assert rest == b''


class SequenceDecoderWithUntaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.Any(), openType=openType)
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 1, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 16, 2, 1, 2, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 2
        assert s[1] == univ.OctetString('quick brown')

    def testDecodeOpenTypesUnknownType(self):
        try:
            s, r = decoder.decode(
                bytes((48, 6, 2, 1, 2, 6, 1, 39)), asn1Spec=self.s,
                decodeOpenTypes=True
            )

        except PyAsn1Error:
            pass

        else:
            assert False, 'unknown open type tolerated'

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 3, 6, 1, 39)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='060127')

    def testDontDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 1, 2, 1, 12)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 1
        assert s[1] == bytes((2, 1, 12))

    def testDontDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 16, 2, 1, 2, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 2
        assert s[1] == bytes((4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110))


class SequenceDecoderWithImplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)), openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 131, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 131, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithExplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.Any().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)), openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 163, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 163, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithUnaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.SetOf(componentType=univ.Any()),
                                    openType=openType)
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 49, 3, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 18, 2, 1, 2, 49, 13, 4, 11, 113, 117, 105, 99,
                       107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 2
        assert s[1][0] == univ.OctetString('quick brown')

    def testDecodeOpenTypesUnknownType(self):
        try:
            s, r = decoder.decode(
                bytes((48, 6, 2, 1, 2, 6, 1, 39)), asn1Spec=self.s,
                decodeOpenTypes=True
            )

        except PyAsn1Error:
            pass

        else:
            assert False, 'unknown open type tolerated'

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 49, 3, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010c')

    def testDontDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 49, 3, 2, 1, 12)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == bytes((2, 1, 12))

    def testDontDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 18, 2, 1, 2, 49, 13, 4, 11, 113, 117, 105, 99,
                       107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 2
        assert s[1][0] == bytes((4, 11, 113, 117, 105, 99, 107, 32, 98, 114,
                                     111, 119, 110))


class SequenceDecoderWithImplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.SetOf(
                        componentType=univ.Any().subtype(
                            implicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3))),
                    openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 1, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 3, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithExplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.SetOf(
                        componentType=univ.Any().subtype(
                            explicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3))),
                    openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 1, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes( (48, 10, 2, 1, 3, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010C')


class NestingDepthLimitTestCase(BaseTestCase):
    """Test DER decoder protection against deeply nested structures."""

    def testDefiniteLenNesting(self):
        """Deeply nested definite-length SEQUENCEs must raise PyAsn1Error."""
        inner = b'\x05\x00'  # NULL
        for _ in range(200):
            length = len(inner)
            if length < 128:
                inner = b'\x30' + bytes([length]) + inner
            else:
                length_bytes = length.to_bytes(
                    (length.bit_length() + 7) // 8, 'big')
                inner = b'\x30' + bytes([0x80 | len(length_bytes)]) + \
                    length_bytes + inner
        try:
            decoder.decode(inner)
        except PyAsn1Error:
            pass
        else:
            assert False, 'Deeply nested definite-length SEQUENCEs not rejected'

    def testNoRecursionError(self):
        """Must raise PyAsn1Error, not RecursionError."""
        inner = b'\x05\x00'
        for _ in range(200):
            length = len(inner)
            if length < 128:
                inner = b'\x30' + bytes([length]) + inner
            else:
                length_bytes = length.to_bytes(
                    (length.bit_length() + 7) // 8, 'big')
                inner = b'\x30' + bytes([0x80 | len(length_bytes)]) + \
                    length_bytes + inner
        try:
            decoder.decode(inner)
        except PyAsn1Error:
            pass
        except RecursionError:
            assert False, 'Got RecursionError instead of PyAsn1Error'


class StrictLengthEncodingTestCase(BaseTestCase):
    def testShortFormAccepted(self):
        assert decoder.decode(
            bytes((4, 3, 1, 2, 3)), strict=True
        ) == (bytes((1, 2, 3)), b'')

    def testLongFormAccepted(self):
        # 128 octets genuinely require the long form
        substrate = bytes((4, 0x81, 128)) + bytes(128)
        value, rest = decoder.decode(substrate, strict=True)
        assert value == bytes(128)
        assert rest == b''

    def testLongFormForShortLengthRejected(self):
        # 0x81 0x03 encodes length 3 in long form, short form required
        substrate = bytes((4, 0x81, 3, 1, 2, 3))

        for asn1Spec in None, univ.OctetString():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert 'offset 1' in str(exc)
                assert '10.1' in str(exc)
            else:
                assert 0, 'non-minimal length encoding tolerated'

    def testLeadingZeroLengthOctetsRejected(self):
        # 0x82 0x00 0x80 encodes length 128 with a redundant leading octet
        substrate = bytes((4, 0x82, 0, 128)) + bytes(128)

        try:
            decoder.decode(substrate, strict=True)
        except PyAsn1Error as exc:
            assert 'offset 1' in str(exc)
            assert '10.1' in str(exc)
        else:
            assert 0, 'non-minimal length encoding tolerated'

    def testIndefiniteLengthRejected(self):
        substrate = bytes((0x30, 0x80, 2, 1, 1, 0, 0))

        try:
            decoder.decode(substrate, strict=True)
        except PyAsn1Error as exc:
            assert 'offset 1' in str(exc)
            assert '10.1' in str(exc)
        else:
            assert 0, 'indefinite-length encoding tolerated'

    def testDefaultModeToleratesNonMinimalLength(self):
        assert decoder.decode(
            bytes((4, 0x81, 3, 1, 2, 3))
        ) == (bytes((1, 2, 3)), b'')

    def testBerDecoderAcceptsNonMinimalLength(self):
        assert ber_decoder.decode(
            bytes((4, 0x81, 3, 1, 2, 3))
        ) == (bytes((1, 2, 3)), b'')

    def testBerDecoderAcceptsIndefiniteLength(self):
        value, rest = ber_decoder.decode(
            bytes((0x30, 0x80, 2, 1, 1, 0, 0)))
        assert value == [1]
        assert rest == b''


class StrictIntegerEncodingTestCase(BaseTestCase):
    def testCanonicalEncodingAccepted(self):
        for substrate in (bytes((2, 1, 127)),       # 127
                          bytes((2, 2, 0, 128)),    # 128
                          bytes((2, 1, 0x80)),      # -128
                          bytes((2, 2, 0xff, 127))  # -129
                          ):
            for asn1Spec in None, univ.Integer():
                value, rest = decoder.decode(
                    substrate, asn1Spec=asn1Spec, strict=True)
                assert not rest

    def testRedundantZeroOctetRejected(self):
        # 0x00 0x7f: leading zero octet is redundant
        substrate = bytes((2, 2, 0, 127))

        for asn1Spec in None, univ.Integer():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert 'offset 2' in str(exc)
                assert '8.3.2' in str(exc)
            else:
                assert 0, 'non-minimal INTEGER encoding tolerated'

    def testRedundantFFOctetRejected(self):
        # 0xff 0x80: leading 0xff octet is redundant (value -128)
        substrate = bytes((2, 2, 0xff, 0x80))

        for asn1Spec in None, univ.Integer():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert 'offset 2' in str(exc)
                assert '8.3.2' in str(exc)
            else:
                assert 0, 'non-minimal INTEGER encoding tolerated'

    def testEmptyPayloadRejected(self):
        # zero-length INTEGER payload violates X.690 8.3.1
        substrate = bytes((2, 0))

        for asn1Spec in None, univ.Integer():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert '8.3.1' in str(exc)
            else:
                assert 0, 'empty INTEGER payload tolerated'

    def testEnumeratedNonMinimalEncodingRejected(self):
        # ENUMERATED shares the INTEGER encoding rules (X.690 8.4)
        substrate = bytes((10, 2, 0, 5))

        try:
            decoder.decode(
                substrate, asn1Spec=univ.Enumerated(), strict=True)
        except PyAsn1Error as exc:
            assert '8.3.2' in str(exc)
        else:
            assert 0, 'non-minimal ENUMERATED encoding tolerated'

    def testDefaultModeToleratesNonMinimalEncoding(self):
        assert decoder.decode(bytes((2, 2, 0, 127))) == (127, b'')

    def testBerDecoderAcceptsNonMinimalEncoding(self):
        assert ber_decoder.decode(bytes((2, 2, 0, 127))) == (127, b'')


class StrictBooleanEncodingTestCase(BaseTestCase):
    def testCanonicalEncodingAccepted(self):
        for substrate, expected in ((bytes((1, 1, 0)), 0),
                                    (bytes((1, 1, 0xff)), 1)):
            for asn1Spec in None, univ.Boolean():
                value, rest = decoder.decode(
                    substrate, asn1Spec=asn1Spec, strict=True)
                assert value == expected
                assert not rest

    def testNonCanonicalTrueRejected(self):
        # BER allows any non-zero octet for TRUE, DER requires 0xff
        substrate = bytes((1, 1, 1))

        for asn1Spec in None, univ.Boolean():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert 'offset 2' in str(exc)
                assert '11.1' in str(exc)
            else:
                assert 0, 'non-canonical BOOLEAN encoding tolerated'

    def testDefaultModeSchemaDrivenPathTolerates(self):
        # the schema-driven dispatch historically bypasses the CER/DER
        # BOOLEAN check; strict mode closes that gap
        assert decoder.decode(
            bytes((1, 1, 1)), asn1Spec=univ.Boolean()) == (1, b'')

    def testBerDecoderAcceptsNonCanonicalTrue(self):
        assert ber_decoder.decode(bytes((1, 1, 1))) == (1, b'')


class StrictConstructedStringTestCase(BaseTestCase):
    def testConstructedOctetStringRejected(self):
        substrate = bytes((0x24, 6, 4, 1, 97, 4, 1, 98))

        for asn1Spec in None, univ.OctetString():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert 'offset 0' in str(exc)
                assert '10.2' in str(exc)
            else:
                assert 0, 'constructed OCTET STRING encoding tolerated'

    def testConstructedBitStringRejected(self):
        substrate = bytes((0x23, 8, 3, 2, 0, 169, 3, 2, 1, 138))

        for asn1Spec in None, univ.BitString():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert '10.2' in str(exc)
            else:
                assert 0, 'constructed BIT STRING encoding tolerated'

    def testConstructedUtf8StringRejected(self):
        substrate = bytes((0x2c, 6, 12, 1, 97, 12, 1, 98))

        for asn1Spec in None, char.UTF8String():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert '10.2' in str(exc)
            else:
                assert 0, 'constructed UTF8String encoding tolerated'

    def testPrimitiveStringsAccepted(self):
        assert decoder.decode(
            bytes((4, 2, 97, 98)), strict=True) == (b'ab', b'')
        assert decoder.decode(
            bytes((12, 2, 97, 98)), asn1Spec=char.UTF8String(),
            strict=True) == ('ab', b'')

    def testDefaultModeSchemaDrivenPathTolerates(self):
        substrate = bytes((0x24, 6, 4, 1, 97, 4, 1, 98))
        assert decoder.decode(
            substrate, asn1Spec=univ.OctetString()) == (b'ab', b'')

    def testBerDecoderAcceptsConstructedForm(self):
        substrate = bytes((0x24, 6, 4, 1, 97, 4, 1, 98))
        assert ber_decoder.decode(substrate) == (b'ab', b'')


class StrictSetOfOrderingTestCase(BaseTestCase):
    substrate = bytes((0x31, 9, 2, 1, 2, 2, 1, 3, 2, 1, 1))  # {2, 3, 1}

    def testOrderedEncodingAccepted(self):
        substrate = bytes((0x31, 9, 2, 1, 1, 2, 1, 2, 2, 1, 3))

        for asn1Spec in None, univ.SetOf(componentType=univ.Integer()):
            value, rest = decoder.decode(
                substrate, asn1Spec=asn1Spec, strict=True)
            assert list(value) == [1, 2, 3]
            assert not rest

    def testUnorderedEncodingRejected(self):
        for asn1Spec in None, univ.SetOf(componentType=univ.Integer()):
            try:
                decoder.decode(
                    self.substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert 'offset 8' in str(exc)
                assert '11.6' in str(exc)
            else:
                assert 0, 'unsorted SET OF encoding tolerated'

    def testDuplicateComponentsAccepted(self):
        substrate = bytes((0x31, 6, 2, 1, 1, 2, 1, 1))
        value, rest = decoder.decode(substrate, strict=True)
        assert list(value) == [1, 1]
        assert not rest

    def testDefaultModeToleratesUnorderedEncoding(self):
        value, rest = decoder.decode(self.substrate)
        assert list(value) == [2, 3, 1]

    def testBerDecoderAcceptsUnorderedEncoding(self):
        value, rest = ber_decoder.decode(self.substrate)
        assert list(value) == [2, 3, 1]


class StrictSetOrderingTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.s = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.OctetString())
            )
        )

    def testOrderedEncodingAccepted(self):
        # INTEGER (tag 2) sorts before OCTET STRING (tag 4)
        substrate = bytes((0x31, 8, 2, 1, 5, 4, 3, 1, 2, 3))

        for asn1Spec in None, self.s:
            value, rest = decoder.decode(
                substrate, asn1Spec=asn1Spec, strict=True)
            assert not rest

    def testUnorderedEncodingRejected(self):
        # OCTET STRING component encoded before INTEGER component
        substrate = bytes((0x31, 8, 4, 3, 1, 2, 3, 2, 1, 5))

        for asn1Spec in None, self.s:
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec, strict=True)
            except PyAsn1Error as exc:
                assert 'offset 7' in str(exc)
                assert '11.5' in str(exc)
            else:
                assert 0, 'unsorted SET encoding tolerated'

    def testBerDecoderAcceptsUnorderedEncoding(self):
        substrate = bytes((0x31, 8, 4, 3, 1, 2, 3, 2, 1, 5))
        value, rest = ber_decoder.decode(substrate, asn1Spec=self.s)
        assert value['a'] == 5
        assert value['b'] == bytes((1, 2, 3))


class StrictStreamingDecoderTestCase(BaseTestCase):
    """Strict checks must not be bypassable by chunked streaming input."""

    class NonBlockingStream(io.BytesIO):
        block = False

        def read(self, size=-1):
            self.block = not self.block
            if self.block:
                return  # this is what non-blocking streams sometimes do

            return io.BytesIO.read(self, size)

    def testCanonicalEncodingAccepted(self):
        stream = self.NonBlockingStream(bytes((2, 1, 5)))
        values = [
            value for value in decoder.StreamingDecoder(stream, strict=True)
            if not isinstance(value, SubstrateUnderrunError)
        ]
        assert values == [5]

    def testNonMinimalIntegerRejected(self):
        stream = self.NonBlockingStream(bytes((2, 2, 0, 127)))

        try:
            list(decoder.StreamingDecoder(stream, strict=True))
        except PyAsn1Error as exc:
            assert '8.3.2' in str(exc)
        else:
            assert 0, 'non-minimal INTEGER encoding tolerated'

    def testNonMinimalLengthRejected(self):
        stream = self.NonBlockingStream(bytes((4, 0x81, 3, 1, 2, 3)))

        try:
            list(decoder.StreamingDecoder(stream, strict=True))
        except PyAsn1Error as exc:
            assert '10.1' in str(exc)
        else:
            assert 0, 'non-minimal length encoding tolerated'

    def testUnorderedSetOfRejected(self):
        substrate = bytes((0x31, 9, 2, 1, 2, 2, 1, 3, 2, 1, 1))
        stream = self.NonBlockingStream(substrate)

        try:
            list(decoder.StreamingDecoder(stream, strict=True))
        except PyAsn1Error as exc:
            assert '11.6' in str(exc)
        else:
            assert 0, 'unsorted SET OF encoding tolerated'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
