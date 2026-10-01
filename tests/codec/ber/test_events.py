#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.codec.ber import events
from pyasn1.error import EndOfStreamError
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ


class BoundedReadStream(io.BytesIO):
    """A stream that refuses to serve more than `maxReadSize` octets at once."""

    def __init__(self, data, maxReadSize):
        io.BytesIO.__init__(self, data)
        self.maxReadSize = maxReadSize
        self.readSizes = []

    def read(self, size=-1):
        if size < 0 or size > self.maxReadSize:
            raise AssertionError('read of %s octets attempted' % (size,))

        self.readSizes.append(size)

        return io.BytesIO.read(self, size)


class NonBlockingStream(io.BytesIO):
    block = False

    def read(self, size=-1):
        self.block = not self.block
        if self.block:
            return  # this is what non-blocking streams sometimes do

        return io.BytesIO.read(self, size)


def envelopeSchema():
    class Envelope(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer()),
            namedtype.NamedType('big', univ.OctetString()),
            namedtype.NamedType('b', univ.Integer())
        )

    return Envelope()


def messageSchema():
    class Body(univ.Choice):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('text', univ.OctetString()),
            namedtype.NamedType('num', univ.Integer())
        )

    class Message(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('blob', univ.OctetString().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 3))),
            namedtype.NamedType('body', Body()),
            namedtype.NamedType('tail', univ.Integer())
        )

    return Message()


# 30 80 | 02 01 05 | A3 80 04 03 AA BB CC 00 00 | 02 01 07 | 02 01 08 | 00 00
MESSAGE_SUBSTRATE = bytes((
    0x30, 0x80,
    0x02, 0x01, 0x05,
    0xA3, 0x80, 0x04, 0x03, 0xAA, 0xBB, 0xCC, 0x00, 0x00,
    0x02, 0x01, 0x07,
    0x02, 0x01, 0x08,
    0x00, 0x00,
))


def collectEvents(decoder):
    """Drive an EventDecoder to exhaustion, dropping underrun sentinels."""
    emitted = []
    underruns = 0

    for event in decoder:
        if isinstance(event, SubstrateUnderrunError):
            underruns += 1
        else:
            emitted.append(event)

    return emitted, underruns


class LargeFieldSkippingTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        self.schema = envelopeSchema()

        big = b'\x55' * 1048576

        # 30 83 10 00 0B | 02 01 2A | 04 83 10 00 00 <1 MiB> | 02 01 2B
        self.substrate = (
            b'\x30\x83\x10\x00\x0b'
            b'\x02\x01\x2a'
            b'\x04\x83\x10\x00\x00' + big +
            b'\x02\x01\x2b'
        )

    def testSelectedFieldsAroundLargeValue(self):
        stream = BoundedReadStream(self.substrate, events.SKIP_CHUNK_SIZE)

        emitted, _ = collectEvents(events.EventDecoder(
            stream, asn1Spec=self.schema, select=[('a',), ('b',)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'value', 'skip', 'value', 'exit']

        assert emitted[0].path == ()
        assert emitted[0].offset == 0
        assert emitted[0].length == 1048587

        assert emitted[1].path == ('a',)
        assert emitted[1].offset == 5
        assert emitted[1].length == 3
        assert emitted[1].value == 42

        assert emitted[2].path == ('big',)
        assert emitted[2].offset == 8
        assert emitted[2].length == 1048581
        assert emitted[2].value is None

        assert emitted[3].path == ('b',)
        assert emitted[3].offset == 1048589
        assert emitted[3].length == 3
        assert emitted[3].value == 43

        assert emitted[4].path == ()
        assert emitted[4].offset == 1048592

    def testLargeValueNeverReadWholesale(self):
        stream = BoundedReadStream(self.substrate, events.SKIP_CHUNK_SIZE)

        emitted, _ = collectEvents(events.EventDecoder(
            stream, asn1Spec=self.schema, select=[('a',), ('b',)]))

        assert stream.readSizes
        assert max(stream.readSizes) <= events.SKIP_CHUNK_SIZE
        assert sum(stream.readSizes) >= 1048576

    def testValuesMatchStockDecoder(self):
        asn1Object, _ = decoder.decode(self.substrate, asn1Spec=self.schema)

        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(self.substrate), asn1Spec=self.schema,
            select=[('a',), ('b',)]))

        values = [event.value for event in emitted if event.kind == 'value']

        assert values[0] == asn1Object['a']
        assert values[1] == asn1Object['b']


class ExplicitChoiceIndefiniteTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        self.schema = messageSchema()

    def testExplicitChoiceIndefiniteTraversal(self):
        emitted, underruns = collectEvents(events.EventDecoder(
            NonBlockingStream(MESSAGE_SUBSTRATE), asn1Spec=self.schema,
            select=[('id',), ('body', 'num'), ('tail',)]))

        # the alternating non-blocking stream must have suspended the
        # decoder, including inside the end-of-octets probes
        assert underruns > 0

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'value', 'skip', 'enter', 'value',
                         'exit', 'value', 'exit']

        assert emitted[0].path == ()
        assert emitted[0].offset == 0
        assert emitted[0].length == -1

        assert emitted[1].path == ('id',)
        assert emitted[1].offset == 2
        assert emitted[1].value == 5

        # explicitly tagged, indefinite-length wrapper skipped whole
        assert emitted[2].path == ('blob',)
        assert emitted[2].offset == 5
        assert emitted[2].length == 9

        assert emitted[3].path == ('body',)
        assert emitted[3].offset == 14

        assert emitted[4].path == ('body', 'num')
        assert emitted[4].offset == 14
        assert emitted[4].value == 7

        assert emitted[5].path == ('body',)
        assert emitted[5].offset == 17

        assert emitted[6].path == ('tail',)
        assert emitted[6].offset == 17
        assert emitted[6].value == 8

        assert emitted[7].path == ()
        assert emitted[7].offset == 22

    def testDecodeThroughExplicitTag(self):
        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(MESSAGE_SUBSTRATE), asn1Spec=self.schema,
            select=[('blob',)]))

        values = [event for event in emitted if event.kind == 'value']

        assert len(values) == 1
        assert values[0].path == ('blob',)
        assert values[0].offset == 5
        assert values[0].length == 9
        assert values[0].value.asOctets() == b'\xaa\xbb\xcc'


class ConstructedSkipTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        self.schema = envelopeSchema()

    def testConstructedIndefiniteOctetStringSkip(self):
        # 30 12 | 02 01 01 | 24 80 04 02 AA BB 04 02 CC DD 00 00 | 02 01 02
        substrate = bytes((
            0x30, 0x12,
            0x02, 0x01, 0x01,
            0x24, 0x80, 0x04, 0x02, 0xAA, 0xBB, 0x04, 0x02, 0xCC, 0xDD,
            0x00, 0x00,
            0x02, 0x01, 0x02,
        ))

        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(substrate), asn1Spec=self.schema,
            select=[('a',), ('b',)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'value', 'skip', 'value', 'exit']

        # constructed, indefinite-length OCTET STRING skipped to its EOC
        assert emitted[2].path == ('big',)
        assert emitted[2].offset == 5
        assert emitted[2].length == 12

        assert emitted[3].path == ('b',)
        assert emitted[3].offset == 17
        assert emitted[3].value == 2

        assert emitted[4].offset == 20


class SequenceOfSelectionTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        self.schema = univ.SequenceOf(componentType=univ.Integer())

        # 30 09 | 02 01 01 | 02 01 02 | 02 01 03
        self.substrate = bytes((
            0x30, 0x09,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x02,
            0x02, 0x01, 0x03,
        ))

    def testItemSelectedByIndex(self):
        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(self.substrate), asn1Spec=self.schema, select=[(2,)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'skip', 'skip', 'value', 'exit']

        assert emitted[1].path == (0,)
        assert emitted[1].offset == 2

        assert emitted[2].path == (1,)
        assert emitted[2].offset == 5

        assert emitted[3].path == (2,)
        assert emitted[3].offset == 8
        assert emitted[3].value == 3

    def testEmptySelectSkipsEverything(self):
        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(self.substrate), asn1Spec=self.schema))

        assert len(emitted) == 1
        assert emitted[0].kind == 'skip'
        assert emitted[0].path == ()
        assert emitted[0].offset == 0
        assert emitted[0].length == 11

    def testRootSelectDecodesEverything(self):
        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(self.substrate), asn1Spec=self.schema, select=[()]))

        assert len(emitted) == 1
        assert emitted[0].kind == 'value'
        assert emitted[0].path == ()
        assert emitted[0].offset == 0
        assert emitted[0].length == 11
        assert list(emitted[0].value) == [1, 2, 3]


class SetSelectionTestCase(BaseTestCase):

    def testUnorderedComponents(self):
        class Record(univ.Set):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.OctetString())
            )

        # 31 07 | 04 02 AA BB | 02 01 05
        substrate = bytes((
            0x31, 0x07,
            0x04, 0x02, 0xAA, 0xBB,
            0x02, 0x01, 0x05,
        ))

        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(substrate), asn1Spec=Record(), select=[('a',)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'skip', 'value', 'exit']

        assert emitted[1].path == ('b',)
        assert emitted[1].offset == 2

        assert emitted[2].path == ('a',)
        assert emitted[2].offset == 6
        assert emitted[2].value == 5


class OptionalComponentsTestCase(BaseTestCase):

    def testAbsentOptionalComponent(self):
        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.OctetString()),
                namedtype.NamedType('c', univ.Integer())
            )

        # 30 07 | 04 02 AA BB | 02 01 07
        substrate = bytes((
            0x30, 0x07,
            0x04, 0x02, 0xAA, 0xBB,
            0x02, 0x01, 0x07,
        ))

        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(substrate), asn1Spec=Record(), select=[('c',)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'skip', 'value', 'exit']

        assert emitted[1].path == ('b',)
        assert emitted[1].offset == 2

        assert emitted[2].path == ('c',)
        assert emitted[2].offset == 6
        assert emitted[2].value == 7


class BoundaryViolationTestCase(BaseTestCase):

    def testChildLengthOverrunsParent(self):
        # 30 08 | 02 01 01 | 04 64 ... -- the OCTET STRING claims 100
        # content octets while the SEQUENCE ends 3 octets later
        substrate = bytes((
            0x30, 0x08,
            0x02, 0x01, 0x01,
            0x04, 0x64,
        )) + b'\x00' * 10

        try:
            collectEvents(events.EventDecoder(
                io.BytesIO(substrate), asn1Spec=envelopeSchema(),
                select=[('b',)]))
        except PyAsn1Error as exc:
            assert 'extends past the end of its enclosing' in str(exc)
        else:
            assert False, 'Parent container boundary overrun tolerated'

    def testTruncatedIndefiniteContainer(self):
        # 30 80 | 02 01 01 | 04 02 AA BB -- end-of-octets never arrives
        substrate = bytes((
            0x30, 0x80,
            0x02, 0x01, 0x01,
            0x04, 0x02, 0xAA, 0xBB,
        ))

        try:
            collectEvents(events.EventDecoder(
                io.BytesIO(substrate), asn1Spec=envelopeSchema(),
                select=[('a',)]))
        except EndOfStreamError:
            pass
        else:
            assert False, 'Truncated indefinite-length container tolerated'


class SelectionErrorTestCase(BaseTestCase):

    def testSelectionBelowScalar(self):
        substrate = bytes((
            0x30, 0x03,
            0x02, 0x01, 0x01,
        ))

        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer())
            )

        try:
            collectEvents(events.EventDecoder(
                io.BytesIO(substrate), asn1Spec=Record(),
                select=[('a', 'x')]))
        except PyAsn1Error as exc:
            assert 'does not resolve to a constructed' in str(exc)
        else:
            assert False, 'Selection path below a scalar field tolerated'

    def testMissingSchemaRejected(self):
        try:
            events.EventDecoder(io.BytesIO(b'\x30\x00'))
        except PyAsn1Error:
            pass
        else:
            assert False, 'Schema-less event decoding tolerated'


class ExplicitlyTaggedContainerTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        class Inner(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('x', univ.Integer()),
                namedtype.NamedType('y', univ.OctetString())
            )

        class Message(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('wrap', Inner().subtype(
                    explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 5))),
                namedtype.NamedType('z', univ.Integer())
            )

        self.schema = Message()

        message = Message()
        message['wrap']['x'] = 1
        message['wrap']['y'] = b'\xaa\xbb'
        message['z'] = 3

        # 30 0E | A5 09 | 30 07 02 01 01 04 02 AA BB | 02 01 03
        self.substrate = encoder.encode(message)

    def testTraverseThroughExplicitWrapper(self):
        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(self.substrate), asn1Spec=self.schema,
            select=[('wrap', 'x'), ('z',)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'enter', 'value', 'skip', 'exit',
                         'value', 'exit']

        assert emitted[1].path == ('wrap',)
        assert emitted[1].offset == 2

        assert emitted[2].path == ('wrap', 'x')
        assert emitted[2].offset == 6
        assert emitted[2].value == 1

        assert emitted[3].path == ('wrap', 'y')
        assert emitted[3].offset == 9

        assert emitted[5].path == ('z',)
        assert emitted[5].offset == 13
        assert emitted[5].value == 3

    def testSkipExplicitWrapperWhole(self):
        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(self.substrate), asn1Spec=self.schema,
            select=[('z',)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'skip', 'value', 'exit']

        assert emitted[1].path == ('wrap',)
        assert emitted[1].offset == 2
        assert emitted[1].length == 11

    def testDecodeExplicitWrapperWhole(self):
        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(self.substrate), asn1Spec=self.schema,
            select=[('wrap',)]))

        values = [event for event in emitted if event.kind == 'value']

        assert len(values) == 1
        assert values[0].path == ('wrap',)
        assert values[0].value['x'] == 1
        assert values[0].value['y'].asOctets() == b'\xaa\xbb'


class TaggedChoiceTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        class Body(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('text', univ.OctetString()),
                namedtype.NamedType('num', univ.Integer())
            )

        class Message(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('body', Body().subtype(
                    explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0))),
                namedtype.NamedType('tail', univ.Integer())
            )

        self.schema = Message()

    def testDefiniteLengthTaggedChoice(self):
        # 30 08 | A0 03 02 01 07 | 02 01 08
        substrate = bytes((
            0x30, 0x08,
            0xA0, 0x03, 0x02, 0x01, 0x07,
            0x02, 0x01, 0x08,
        ))

        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(substrate), asn1Spec=self.schema,
            select=[('body', 'num'), ('tail',)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'enter', 'value', 'exit', 'value', 'exit']

        assert emitted[1].path == ('body',)
        assert emitted[1].offset == 2

        assert emitted[2].path == ('body', 'num')
        assert emitted[2].offset == 4
        assert emitted[2].value == 7

        assert emitted[4].path == ('tail',)
        assert emitted[4].offset == 7
        assert emitted[4].value == 8

    def testIndefiniteLengthTaggedChoice(self):
        # 30 80 | A0 80 02 01 07 00 00 | 02 01 08 | 00 00
        substrate = bytes((
            0x30, 0x80,
            0xA0, 0x80, 0x02, 0x01, 0x07, 0x00, 0x00,
            0x02, 0x01, 0x08,
            0x00, 0x00,
        ))

        emitted, _ = collectEvents(events.EventDecoder(
            io.BytesIO(substrate), asn1Spec=self.schema,
            select=[('body', 'num'), ('tail',)]))

        kinds = [event.kind for event in emitted]
        assert kinds == ['enter', 'enter', 'value', 'exit', 'value', 'exit']

        assert emitted[2].path == ('body', 'num')
        assert emitted[2].offset == 4
        assert emitted[2].value == 7

        assert emitted[4].path == ('tail',)
        assert emitted[4].offset == 9
        assert emitted[4].value == 8

        assert emitted[5].offset == 14


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
