#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import json
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.codec.json import encoder
from pyasn1.error import PyAsn1Error


class BadAsn1SpecTestCase(BaseTestCase):
    def testBadValueType(self):
        try:
            encoder.encode('not an Asn1Item')

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Invalid value type accepted'


class IntegerEncoderTestCase(BaseTestCase):
    def testPosInt(self):
        assert encoder.encode(univ.Integer(12)) == {'$int': '12'}

    def testNegInt(self):
        assert encoder.encode(univ.Integer(-12)) == {'$int': '-12'}

    def testBigInt(self):
        big = 2 ** 100
        assert encoder.encode(univ.Integer(big)) == {'$int': str(big)}

    def testHugeIntHexFallback(self):
        # decimal rendering of this integer exceeds the interpreter's
        # int-to-str conversion limit on Python 3.11+; the payload
        # renderer falls back to hexadecimal (a full encode() of such
        # a value additionally trips the debug logger's prettyPrint(),
        # a pre-existing limitation shared with the BER family)
        huge = 1 << 20000
        assert encoder._renderInteger(huge) == hex(huge)
        assert encoder._renderInteger(-huge) == hex(-huge)

    def testEnumerated(self):
        assert encoder.encode(univ.Enumerated(3)) == {'$int': '3'}


class BooleanEncoderTestCase(BaseTestCase):
    def testTrue(self):
        assert encoder.encode(univ.Boolean(1)) is True

    def testFalse(self):
        assert encoder.encode(univ.Boolean(0)) is False


class BitStringEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.b = univ.BitString((1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1))

    def testValue(self):
        assert encoder.encode(self.b) == {'$bits': '101010011000101'}

    def testEffectiveBitLength(self):
        # the payload length is the effective number of bits
        assert len(encoder.encode(self.b)['$bits']) == len(self.b)

    def testEmpty(self):
        assert encoder.encode(univ.BitString(())) == {'$bits': ''}


class OctetStringEncoderTestCase(BaseTestCase):
    def testValue(self):
        assert encoder.encode(univ.OctetString(b'\x01\x02\xff')) == {
            '$bytes': 'AQL/'}

    def testEmpty(self):
        assert encoder.encode(univ.OctetString('')) == {'$bytes': ''}


class NullEncoderTestCase(BaseTestCase):
    def testNull(self):
        assert encoder.encode(univ.Null('')) is None


class ObjectIdentifierEncoderTestCase(BaseTestCase):
    def testValue(self):
        assert encoder.encode(univ.ObjectIdentifier('1.2.840.113549')) == {
            '$oid': '1.2.840.113549'}

    def testRelativeOid(self):
        assert encoder.encode(univ.RelativeOID('1.2.3')) == {'$oid': '1.2.3'}


class RealEncoderTestCase(BaseTestCase):
    def testValue(self):
        assert encoder.encode(univ.Real(1.5)) == {'$real': '1.5'}

    def testInf(self):
        assert encoder.encode(univ.Real('inf')) == {'$real': 'inf'}

    def testMinusInf(self):
        assert encoder.encode(univ.Real('-inf')) == {'$real': '-inf'}


class TextStringEncoderTestCase(BaseTestCase):
    def testUtf8(self):
        assert encoder.encode(char.UTF8String('abc')) == 'abc'

    def testPrintable(self):
        assert encoder.encode(char.PrintableString('abc')) == 'abc'


class SequenceOfEncoderTestCase(BaseTestCase):
    def testValue(self):
        seq = univ.SequenceOf(componentType=univ.Integer())
        seq.extend([1, 2, 3])
        assert encoder.encode(seq) == [
            {'$int': '1'}, {'$int': '2'}, {'$int': '3'}]

    def testEmpty(self):
        seq = univ.SequenceOf(componentType=univ.Integer())
        assert encoder.encode(seq) == []


class SequenceEncoderTestCase(BaseTestCase):
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
        record = self.schema()
        record['id'] = 1
        record['blob'] = b'\x01'
        record['level'] = 3
        assert encoder.encode(record) == {
            'id': {'$int': '1'}, 'blob': {'$bytes': 'AQ=='},
            'level': {'$int': '3'}}

    def testMissingOptionalOmitted(self):
        record = self.schema()
        record['id'] = 1
        record['level'] = 3
        assert encoder.encode(record) == {
            'id': {'$int': '1'}, 'level': {'$int': '3'}}

    def testMissingDefaultedOmitted(self):
        record = self.schema()
        record['id'] = 1
        assert encoder.encode(record) == {'id': {'$int': '1'}}

    def testEncodeDoesNotMaterializeDefaults(self):
        record = self.schema()
        record['id'] = 1
        encoder.encode(record)
        assert record.getComponentByPosition(1, instantiate=False) is univ.noValue
        assert record.getComponentByPosition(2, instantiate=False) is univ.noValue

    def testMissingMandatory(self):
        record = self.schema()
        record['blob'] = b'\x01'
        try:
            encoder.encode(record)

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Missing mandatory component tolerated'


class ChoiceEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        class Payload(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('text', char.UTF8String()),
                namedtype.NamedType('number', univ.Integer())
            )

        self.schema = Payload

    def testSelectedBranch(self):
        payload = self.schema()
        payload['number'] = 5
        assert encoder.encode(payload) == {'$choice': {'number': {'$int': '5'}}}

    def testNoBranchChosen(self):
        try:
            encoder.encode(self.schema())

        except PyAsn1Error:
            pass

        else:
            assert 0, 'Unchosen CHOICE tolerated'


class AnyEncoderTestCase(BaseTestCase):
    def testValue(self):
        assert encoder.encode(univ.Any(b'\x05\x00')) == {'$bytes': 'BQA='}


class CanonicalFormTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('name', char.UTF8String()),
                namedtype.NamedType('tags', univ.SequenceOf(
                    componentType=univ.Integer()))
            )

        record = Record()
        record['id'] = 2 ** 100
        record['tags'].extend([3, 1, 2])
        self.record = record

    def testRepeatedEncodeStable(self):
        assert encoder.encode(self.record) == encoder.encode(self.record)

    def testJsonSerializable(self):
        json.dumps(encoder.encode(self.record))

    def testJsonDocumentStable(self):
        first = json.dumps(encoder.encode(self.record), sort_keys=True)
        second = json.dumps(encoder.encode(self.record), sort_keys=True)
        assert first == second


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
