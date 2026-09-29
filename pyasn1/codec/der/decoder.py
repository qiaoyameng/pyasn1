#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import warnings

from pyasn1 import error
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.cer import decoder
from pyasn1.codec.der import encoder
from pyasn1.codec.streaming import readFromStream
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

__all__ = ['decode', 'StreamingDecoder']


class BitStringPayloadDecoder(decoder.BitStringPayloadDecoder):
    supportConstructedForm = False


class OctetStringPayloadDecoder(decoder.OctetStringPayloadDecoder):
    supportConstructedForm = False


# TODO: prohibit non-canonical encoding
RealPayloadDecoder = decoder.RealPayloadDecoder


class StrictIntegerPayloadDecoder(ber_decoder.IntegerPayloadDecoder):
    """INTEGER decoder rejecting non-minimal two's-complement encodings."""

    def valueDecoder(self, substrate, asn1Spec,
                     tagSet=None, length=None, state=None,
                     decodeFun=None, substrateFun=None,
                     **options):

        if tagSet[0].tagFormat != tag.tagFormatSimple:
            raise error.PyAsn1Error('Simple tag format expected')

        offset = substrate.tell()

        for chunk in readFromStream(substrate, length, options):
            if isinstance(chunk, error.SubstrateUnderrunError):
                yield chunk

        if not chunk:
            raise error.PyAsn1Error(
                'DER restriction violated at offset %d: INTEGER payload '
                'must be at least one octet (X.690 8.3.1)' % offset)

        if len(chunk) > 1:
            if chunk[0] == 0x00 and not chunk[1] & 0x80:
                raise error.PyAsn1Error(
                    'DER restriction violated at offset %d: INTEGER payload '
                    'is not minimally encoded (X.690 8.3.2)' % offset)

            if chunk[0] == 0xff and chunk[1] & 0x80:
                raise error.PyAsn1Error(
                    'DER restriction violated at offset %d: INTEGER payload '
                    'is not minimally encoded (X.690 8.3.2)' % offset)

        value = int.from_bytes(bytes(chunk), 'big', signed=True)

        yield self._createComponent(asn1Spec, tagSet, value, **options)


class StrictBooleanPayloadDecoder(decoder.BooleanPayloadDecoder):
    """BOOLEAN decoder enforcing the canonical DER true value."""

    def valueDecoder(self, substrate, asn1Spec,
                     tagSet=None, length=None, state=None,
                     decodeFun=None, substrateFun=None,
                     **options):

        offset = substrate.tell()

        if length != 1:
            raise error.PyAsn1Error(
                'DER restriction violated at offset %d: BOOLEAN payload '
                'must be a single octet (X.690 8.2.1)' % offset)

        for chunk in readFromStream(substrate, length, options):
            if isinstance(chunk, error.SubstrateUnderrunError):
                yield chunk

        byte = chunk[0]

        # DER (like CER) requires TRUE to be encoded as 0xff, while BER
        # allows any non-zero value (X.690 11.1)
        if byte == 0xff:
            value = 1

        elif byte == 0x00:
            value = 0

        else:
            raise error.PyAsn1Error(
                'DER restriction violated at offset %d: BOOLEAN TRUE must '
                'be encoded as 0xff (X.690 11.1)' % offset)

        yield self._createComponent(asn1Spec, tagSet, value, **options)


class StrictStringPayloadDecoderMixin(object):
    """Prohibit the constructed form of string encoding (X.690 10.2)."""

    supportConstructedForm = False

    def valueDecoder(self, substrate, asn1Spec,
                     tagSet=None, length=None, state=None,
                     decodeFun=None, substrateFun=None,
                     **options):
        if tagSet[0].tagFormat != tag.tagFormatSimple:
            raise error.PyAsn1Error(
                'DER restriction violated at offset %d: constructed form '
                'of string encoding is prohibited (X.690 10.2)' % (
                    substrate.markedPosition,))

        parentDecoder = super(StrictStringPayloadDecoderMixin, self)

        for chunk in parentDecoder.valueDecoder(
                substrate, asn1Spec, tagSet=tagSet, length=length,
                state=state, decodeFun=decodeFun, substrateFun=substrateFun,
                **options):
            yield chunk


class StrictBitStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, BitStringPayloadDecoder):
    pass


class StrictOctetStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, OctetStringPayloadDecoder):
    pass


class StrictUTF8StringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.UTF8StringPayloadDecoder):
    pass


class StrictNumericStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.NumericStringPayloadDecoder):
    pass


class StrictPrintableStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.PrintableStringPayloadDecoder):
    pass


class StrictTeletexStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.TeletexStringPayloadDecoder):
    pass


class StrictVideotexStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.VideotexStringPayloadDecoder):
    pass


class StrictIA5StringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.IA5StringPayloadDecoder):
    pass


class StrictGraphicStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.GraphicStringPayloadDecoder):
    pass


class StrictVisibleStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.VisibleStringPayloadDecoder):
    pass


class StrictGeneralStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.GeneralStringPayloadDecoder):
    pass


class StrictUniversalStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.UniversalStringPayloadDecoder):
    pass


class StrictBMPStringPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.BMPStringPayloadDecoder):
    pass


class StrictObjectDescriptorPayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.ObjectDescriptorPayloadDecoder):
    pass


class StrictGeneralizedTimePayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.GeneralizedTimePayloadDecoder):
    pass


class StrictUTCTimePayloadDecoder(
        StrictStringPayloadDecoderMixin, ber_decoder.UTCTimePayloadDecoder):
    pass


class StrictSetPayloadDecoder(ber_decoder.SetPayloadDecoder):
    """SET decoder enforcing ascending tag order of components."""

    def _checkComponentOrder(self, previousComponent, component, offset):
        if component.effectiveTagSet < previousComponent.effectiveTagSet:
            raise error.PyAsn1Error(
                'DER restriction violated at offset %d: SET components are '
                'not in ascending tag order (X.690 11.5)' % offset)


class StrictSetOfPayloadDecoder(ber_decoder.SetOfPayloadDecoder):
    """SET OF decoder enforcing ascending order of component encodings."""

    def _checkComponentOrder(self, previousComponent, component, offset):
        if encoder.encode(component) < encoder.encode(previousComponent):
            raise error.PyAsn1Error(
                'DER restriction violated at offset %d: SET OF components '
                'are not in ascending order of their encodings '
                '(X.690 11.6)' % offset)


class StrictSetOrSetOfPayloadDecoder(ber_decoder.SetOrSetOfPayloadDecoder):
    """Schemaless SET/SET OF decoder enforcing canonical ordering.

    Without a schema, siblings carrying equal tags are checked against
    the SET OF rule (X.690 11.6), the rest against the SET rule
    (X.690 11.5), mirroring the heuristics of the schemaless decoder.
    """

    def _checkComponentOrder(self, previousComponent, component, offset):
        if previousComponent.effectiveTagSet == component.effectiveTagSet:
            if encoder.encode(component) < encoder.encode(previousComponent):
                raise error.PyAsn1Error(
                    'DER restriction violated at offset %d: SET OF '
                    'components are not in ascending order of their '
                    'encodings (X.690 11.6)' % offset)

        elif component.effectiveTagSet < previousComponent.effectiveTagSet:
            raise error.PyAsn1Error(
                'DER restriction violated at offset %d: SET components are '
                'not in ascending tag order (X.690 11.5)' % offset)


TAG_MAP = decoder.TAG_MAP.copy()
TAG_MAP.update(
    {univ.BitString.tagSet: BitStringPayloadDecoder(),
     univ.OctetString.tagSet: OctetStringPayloadDecoder(),
     univ.Real.tagSet: RealPayloadDecoder()}
)

TYPE_MAP = decoder.TYPE_MAP.copy()

# Put in non-ambiguous types for faster codec lookup
for typeDecoder in TAG_MAP.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None and typeId not in TYPE_MAP:
            TYPE_MAP[typeId] = typeDecoder


STRICT_TAG_MAP = TAG_MAP.copy()
STRICT_TAG_MAP.update(
    {univ.Boolean.tagSet: StrictBooleanPayloadDecoder(),
     univ.Integer.tagSet: StrictIntegerPayloadDecoder(),
     univ.Enumerated.tagSet: StrictIntegerPayloadDecoder(),
     univ.BitString.tagSet: StrictBitStringPayloadDecoder(),
     univ.OctetString.tagSet: StrictOctetStringPayloadDecoder(),
     univ.Set.tagSet: StrictSetOrSetOfPayloadDecoder(),
     char.UTF8String.tagSet: StrictUTF8StringPayloadDecoder(),
     char.NumericString.tagSet: StrictNumericStringPayloadDecoder(),
     char.PrintableString.tagSet: StrictPrintableStringPayloadDecoder(),
     char.TeletexString.tagSet: StrictTeletexStringPayloadDecoder(),
     char.VideotexString.tagSet: StrictVideotexStringPayloadDecoder(),
     char.IA5String.tagSet: StrictIA5StringPayloadDecoder(),
     char.GraphicString.tagSet: StrictGraphicStringPayloadDecoder(),
     char.VisibleString.tagSet: StrictVisibleStringPayloadDecoder(),
     char.GeneralString.tagSet: StrictGeneralStringPayloadDecoder(),
     char.UniversalString.tagSet: StrictUniversalStringPayloadDecoder(),
     char.BMPString.tagSet: StrictBMPStringPayloadDecoder(),
     useful.ObjectDescriptor.tagSet: StrictObjectDescriptorPayloadDecoder(),
     useful.GeneralizedTime.tagSet: StrictGeneralizedTimePayloadDecoder(),
     useful.UTCTime.tagSet: StrictUTCTimePayloadDecoder()}
)

STRICT_TYPE_MAP = TYPE_MAP.copy()

# Route schema-driven decoding through the strict decoders as well: the
# inherited TYPE_MAP would otherwise return BER's permissive decoders
for typeDecoder in STRICT_TAG_MAP.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None:
            STRICT_TYPE_MAP[typeId] = typeDecoder

STRICT_TYPE_MAP.update(
    {univ.Set.typeId: StrictSetPayloadDecoder(),
     univ.SetOf.typeId: StrictSetOfPayloadDecoder()}
)


class SingleItemDecoder(decoder.SingleItemDecoder):
    __doc__ = decoder.SingleItemDecoder.__doc__

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP

    supportIndefLength = False


class StrictSingleItemDecoder(SingleItemDecoder):
    __doc__ = SingleItemDecoder.__doc__

    TAG_MAP = STRICT_TAG_MAP
    TYPE_MAP = STRICT_TYPE_MAP

    def _checkLength(self, offset, firstOctet, lengthOctets, length):
        # DER requires the definite form, encoded in the minimum
        # number of octets (X.690 10.1)
        if length == -1:
            raise error.PyAsn1Error(
                'DER restriction violated at offset %d: indefinite-length '
                'encoding is prohibited (X.690 10.1)' % offset)

        if firstOctet > 128:
            if lengthOctets[0] == 0:
                raise error.PyAsn1Error(
                    'DER restriction violated at offset %d: length is not '
                    'encoded in the minimum number of octets '
                    '(X.690 10.1)' % offset)

            if length <= 127:
                raise error.PyAsn1Error(
                    'DER restriction violated at offset %d: long-form '
                    'length used for %d octets, short form required '
                    '(X.690 10.1)' % (offset, length))


class StreamingDecoder(decoder.StreamingDecoder):
    __doc__ = decoder.StreamingDecoder.__doc__

    SINGLE_ITEM_DECODER = SingleItemDecoder

    def __init__(self, substrate, asn1Spec=None, **options):
        if options.pop('strict', False):
            self.SINGLE_ITEM_DECODER = StrictSingleItemDecoder

        decoder.StreamingDecoder.__init__(self, substrate, asn1Spec, **options)


class Decoder(decoder.Decoder):
    __doc__ = decoder.Decoder.__doc__

    STREAMING_DECODER = StreamingDecoder


#: Turns DER octet stream into an ASN.1 object.
#:
#: Takes DER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes`
#:     DER octet-stream
#:
#: Keyword Args
#: ------------
#: asn1Spec: any pyasn1 type object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A pyasn1 type object to act as a template guiding the decoder. Depending on the ASN.1 structure
#:     being decoded, *asn1Spec* may or may not be required. Most common reason for
#:     it to require is that ASN.1 structure is encoded in *IMPLICIT* tagging mode.
#:
#: strict: :py:class:`bool`
#:     Enforce DER-specific encoding restrictions that the decoder otherwise
#:     tolerates: indefinite-length and non-minimal length fields (X.690 10.1),
#:     non-minimal INTEGER contents (X.690 8.3), non-canonical BOOLEAN TRUE
#:     values (X.690 11.1), constructed string encodings (X.690 10.2) and
#:     unsorted SET/SET OF components (X.690 11.5, 11.6). Violations are
#:     rejected with :py:class:`~pyasn1.error.PyAsn1Error` carrying the
#:     stream offset and the violated X.690 clause. Defaults to False,
#:     preserving the historical lenient behavior.
#:
#: Returns
#: -------
#: : :py:class:`tuple`
#:     A tuple of pyasn1 object recovered from DER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode DER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03')
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
#: Decode DER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03', asn1Spec=seq)
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
decode = Decoder()

def __getattr__(attr: str):
    if newAttr := {"tagMap": "TAG_MAP", "typeMap": "TYPE_MAP"}.get(attr):
        warnings.warn(f"{attr} is deprecated. Please use {newAttr} instead.", DeprecationWarning, stacklevel=2)
        return globals()[newAttr]
    raise AttributeError(attr)
