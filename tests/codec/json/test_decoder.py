#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.codec.json import decoder
from pyasn1.codec.json import encoder
from pyasn1.error import PyAsn1Error


class BadAsn1SpecTestCase(BaseTestCase):
    def testNoSpec(self):
        try:
            decoder.decode({'$int': '1'})

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Missing asn1Spec tolerated'

    def testBadSpec(self):
        try:
            decoder.decode({'$int': '1'}, asn1Spec='not an Asn1Item')

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Invalid asn1Spec tolerated'


class IntegerDecoderTestCase(BaseTestCase):
    def testPosInt(self):
        assert decoder.decode(
            {'$int': '12'}, asn1Spec=univ.Integer()) == 12

    def testNegInt(self):
        assert decoder.decode(
            {'$int': '-12'}, asn1Spec=univ.Integer()) == -12

    def testBigInt(self):
        big = 2 ** 100
        assert decoder.decode(
            {'$int': str(big)}, asn1Spec=univ.Integer()) == big

    def testHexInt(self):
        assert decoder.decode(
            {'$int': hex(2 ** 100)}, asn1Spec=univ.Integer()) == 2 ** 100

    def testHugeHexInt(self):
        # hexadecimal payloads are not subject to the interpreter's
        # int-to-str conversion limit; a full decode() of such a value
        # additionally trips the debug logger's prettyPrint(), a
        # pre-existing limitation shared with the BER family
        huge = 1 << 20000
        assert decoder._parseInteger(hex(huge)) == huge
        assert decoder._parseInteger(hex(-huge)) == -huge

    def testEnumerated(self):
        value = decoder.decode({'$int': '3'}, asn1Spec=univ.Enumerated())
        assert isinstance(value, univ.Enumerated)
        assert value == 3

    def testBareIntRejected(self):
        try:
            decoder.decode(12, asn1Spec=univ.Integer())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Untagged integer tolerated'

    def testNonStringPayloadRejected(self):
        try:
            decoder.decode({'$int': 12}, asn1Spec=univ.Integer())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Non-string INTEGER payload tolerated'

    def testBadPayloadRejected(self):
        try:
            decoder.decode({'$int': '12x4'}, asn1Spec=univ.Integer())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Malformed INTEGER payload tolerated'

    def testUnknownTagRejected(self):
        try:
            decoder.decode({'$number': '12'}, asn1Spec=univ.Integer())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Unknown tag tolerated'

    def testMultiKeyTagRejected(self):
        try:
            decoder.decode(
                {'$int': '12', '$oid': '1.2'}, asn1Spec=univ.Integer())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Multi-key tagged object tolerated'

    def testConstraintEnforced(self):
        class Small(univ.Integer):
            subtypeSpec = constraint.ValueRangeConstraint(0, 10)

        try:
            decoder.decode({'$int': '11'}, asn1Spec=Small())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Constraint violation tolerated'


class BooleanDecoderTestCase(BaseTestCase):
    def testTrue(self):
        assert decoder.decode(True, asn1Spec=univ.Boolean()) == 1

    def testFalse(self):
        assert decoder.decode(False, asn1Spec=univ.Boolean()) == 0

    def testIntRejected(self):
        try:
            decoder.decode(1, asn1Spec=univ.Boolean())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Non-boolean tolerated'


class BitStringDecoderTestCase(BaseTestCase):
    def testValue(self):
        bitString = decoder.decode(
            {'$bits': '101010011000101'}, asn1Spec=univ.BitString())
        assert bitString == univ.BitString((1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1))

    def testEffectiveBitLength(self):
        bitString = decoder.decode({'$bits': '101'}, asn1Spec=univ.BitString())
        assert len(bitString) == 3

    def testEmpty(self):
        bitString = decoder.decode({'$bits': ''}, asn1Spec=univ.BitString())
        assert len(bitString) == 0

    def testBadPayloadRejected(self):
        try:
            decoder.decode({'$bits': '102'}, asn1Spec=univ.BitString())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Malformed BIT STRING payload tolerated'


class OctetStringDecoderTestCase(BaseTestCase):
    def testValue(self):
        assert decoder.decode(
            {'$bytes': 'AQL/'}, asn1Spec=univ.OctetString()) == b'\x01\x02\xff'

    def testBadBase64Rejected(self):
        try:
            decoder.decode({'$bytes': 'A?L/'}, asn1Spec=univ.OctetString())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Malformed base64 payload tolerated'

    def testAny(self):
        value = decoder.decode({'$bytes': 'BQA='}, asn1Spec=univ.Any())
        assert value.asOctets() == b'\x05\x00'


class NullDecoderTestCase(BaseTestCase):
    def testNull(self):
        assert decoder.decode(None, asn1Spec=univ.Null()).isValue

    def testNonNullRejected(self):
        try:
            decoder.decode(0, asn1Spec=univ.Null())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Non-null tolerated'


class ObjectIdentifierDecoderTestCase(BaseTestCase):
    def testValue(self):
        assert decoder.decode(
            {'$oid': '1.2.840.113549'},
            asn1Spec=univ.ObjectIdentifier()) == (1, 2, 840, 113549)

    def testRelativeOid(self):
        assert decoder.decode(
            {'$oid': '1.2.3'}, asn1Spec=univ.RelativeOID()) == (1, 2, 3)

    def testBadPayloadRejected(self):
        try:
            decoder.decode(
                {'$oid': 'not.an.oid'}, asn1Spec=univ.ObjectIdentifier())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Malformed OBJECT IDENTIFIER tolerated'


class RealDecoderTestCase(BaseTestCase):
    def testValue(self):
        assert decoder.decode({'$real': '1.5'}, asn1Spec=univ.Real()) == 1.5

    def testInf(self):
        assert decoder.decode(
            {'$real': 'inf'}, asn1Spec=univ.Real()) == float('inf')

    def testNanRejected(self):
        # pyasn1 Real cannot represent NaN
        try:
            decoder.decode({'$real': 'nan'}, asn1Spec=univ.Real())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'NaN REAL payload tolerated'

    def testBadPayloadRejected(self):
        try:
            decoder.decode({'$real': 'not a float'}, asn1Spec=univ.Real())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Malformed REAL payload tolerated'


class TextStringDecoderTestCase(BaseTestCase):
    def testUtf8(self):
        value = decoder.decode('abc', asn1Spec=char.UTF8String())
        assert isinstance(value, char.UTF8String)
        assert value == 'abc'

    def testNonStringRejected(self):
        try:
            decoder.decode({'$bytes': 'YQ=='}, asn1Spec=char.UTF8String())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Non-string tolerated'

    def testConstraintEnforced(self):
        class Code(char.PrintableString):
            subtypeSpec = constraint.ValueSizeConstraint(2, 2)

        try:
            decoder.decode('abc', asn1Spec=Code())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Constraint violation tolerated'


class SequenceDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('blob', univ.OctetString()),
                namedtype.DefaultedNamedType('level', univ.Integer(7))
            )

        self.schema = Record

    def testAllPresent(self):
        record = decoder.decode(
            {'id': {'$int': '1'}, 'blob': {'$bytes': 'AQ=='},
             'level': {'$int': '3'}}, asn1Spec=self.schema())
        assert record['id'] == 1
        assert record['blob'] == b'\x01'
        assert record['level'] == 3

    def testMissingOptionalStaysMissing(self):
        record = decoder.decode({'id': {'$int': '1'}}, asn1Spec=self.schema())
        assert record.getComponentByPosition(1, instantiate=False) is univ.noValue
        assert record.getComponentByPosition(2, instantiate=False) is univ.noValue

    def testUnknownFieldRejected(self):
        try:
            decoder.decode(
                {'id': {'$int': '1'}, 'bogus': {'$int': '2'}},
                asn1Spec=self.schema())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Unknown component tolerated'

    def testTaggedKeyRejected(self):
        # a business dictionary can not impersonate a tagged special
        # value inside a SEQUENCE
        try:
            decoder.decode(
                {'id': {'$int': '1'}, '$int': '2'}, asn1Spec=self.schema())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Tagged key inside SEQUENCE tolerated'

    def testNonObjectRejected(self):
        try:
            decoder.decode([{'$int': '1'}], asn1Spec=self.schema())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Non-object tolerated'


class ChoiceDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        class Payload(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('text', char.UTF8String()),
                namedtype.NamedType('number', univ.Integer())
            )

        self.schema = Payload

    def testSelectedBranch(self):
        payload = decoder.decode(
            {'$choice': {'number': {'$int': '5'}}}, asn1Spec=self.schema())
        assert payload.getName() == 'number'
        assert payload['number'] == 5

    def testUnknownBranchRejected(self):
        try:
            decoder.decode(
                {'$choice': {'bogus': {'$int': '5'}}}, asn1Spec=self.schema())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Unknown CHOICE alternative tolerated'

    def testMultiBranchRejected(self):
        try:
            decoder.decode(
                {'$choice': {'number': {'$int': '5'}, 'text': 'x'}},
                asn1Spec=self.schema())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Multi-alternative CHOICE tolerated'

    def testUntaggedRejected(self):
        try:
            decoder.decode({'number': {'$int': '5'}}, asn1Spec=self.schema())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Untagged CHOICE tolerated'


class SequenceOfDecoderTestCase(BaseTestCase):
    def testValue(self):
        seq = decoder.decode(
            [{'$int': '1'}, {'$int': '2'}],
            asn1Spec=univ.SequenceOf(componentType=univ.Integer()))
        assert list(seq) == [1, 2]

    def testEmpty(self):
        seq = decoder.decode(
            [], asn1Spec=univ.SequenceOf(componentType=univ.Integer()))
        assert len(seq) == 0

    def testNonArrayRejected(self):
        try:
            decoder.decode(
                {'$int': '1'},
                asn1Spec=univ.SequenceOf(componentType=univ.Integer()))

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Non-array tolerated'


class RoundTripTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        class Payload(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('text', char.UTF8String()),
                namedtype.NamedType('number', univ.Integer())
            )

        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('blob', univ.OctetString()),
                namedtype.DefaultedNamedType('level', univ.Integer(7)),
                namedtype.NamedType('oid', univ.ObjectIdentifier()),
                namedtype.NamedType('bits', univ.BitString()),
                namedtype.NamedType('payload', Payload())
            )

        self.payloadSchema = Payload
        self.schema = Record

    def testRoundTripPreservesState(self):
        record = self.schema()
        record['id'] = 2 ** 100
        record['oid'] = '1.2.840.113549'
        record['bits'] = univ.BitString((1, 0, 1, 1, 0))
        payload = self.payloadSchema()
        payload['text'] = 'hello'
        record['payload'] = payload

        tree = encoder.encode(record)
        decoded = decoder.decode(tree, asn1Spec=self.schema())

        assert decoded == record
        # CHOICE branch identity survives
        assert decoded['payload'].getName() == 'text'
        # optional/defaulted absence survives
        assert decoded.getComponentByPosition(1, instantiate=False) is univ.noValue
        assert decoded.getComponentByPosition(2, instantiate=False) is univ.noValue
        # re-encoding the decoded value is byte-stable
        assert encoder.encode(decoded) == tree

    def testRoundTripOtherChoiceBranch(self):
        record = self.schema()
        record['id'] = 1
        record['blob'] = b'\xde\xad'
        record['level'] = 9
        record['oid'] = '2.5.4'
        record['bits'] = univ.BitString(())
        payload = self.payloadSchema()
        payload['number'] = -5
        record['payload'] = payload

        tree = encoder.encode(record)
        decoded = decoder.decode(tree, asn1Spec=self.schema())

        assert decoded == record
        assert decoded['payload'].getName() == 'number'
        assert decoded.getComponentByPosition(1, instantiate=False) is not univ.noValue
        assert decoded.getComponentByPosition(2, instantiate=False) is not univ.noValue
        assert encoder.encode(decoded) == tree


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
