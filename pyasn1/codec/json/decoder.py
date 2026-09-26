#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import base64
import binascii
import math

from pyasn1 import debug
from pyasn1 import error
from pyasn1.codec.json import ALL_TAGS
from pyasn1.codec.json import TAG_BITS
from pyasn1.codec.json import TAG_BYTES
from pyasn1.codec.json import TAG_CHOICE
from pyasn1.codec.json import TAG_INTEGER
from pyasn1.codec.json import TAG_OID
from pyasn1.codec.json import TAG_REAL
from pyasn1.compat import _MISSING
from pyasn1.type import base
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

__all__ = ['decode']

LOG = debug.registerLoggee(__name__, flags=debug.DEBUG_DECODER)


def _parseInteger(text):
    # Decimal parsing of a huge string can exceed the interpreter's
    # int-to-str conversion limit (sys.get_int_max_str_digits(),
    # Python 3.11+) and raise ValueError; hexadecimal is not limited
    try:
        if 'x' in text:
            return int(text, 16)
        return int(text)

    except ValueError:
        raise error.PyAsn1Error(
            'Badly formed INTEGER payload %r' % (text,))


class AbstractPayloadDecoder(object):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        raise error.PyAsn1Error('Not implemented')

    @staticmethod
    def _unwrapTagged(pyObject, tagName, asn1Spec):
        if not isinstance(pyObject, dict) or len(pyObject) != 1:
            raise error.PyAsn1Error(
                'Expected a single-key tagged object {%r: ...} for %s, '
                'got %r' % (tagName, asn1Spec.__class__.__name__, pyObject))

        try:
            return pyObject[tagName]

        except KeyError:
            raise error.PyAsn1Error(
                'Expected tag %r for %s, got %r' % (
                    tagName, asn1Spec.__class__.__name__, pyObject))


class BooleanPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        if not isinstance(pyObject, bool):
            raise error.PyAsn1Error(
                'Expected a JSON boolean for %s, got %r' % (
                    asn1Spec.__class__.__name__, pyObject))

        return asn1Spec.clone(pyObject)


class IntegerPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        payload = self._unwrapTagged(pyObject, TAG_INTEGER, asn1Spec)

        if not isinstance(payload, str):
            raise error.PyAsn1Error(
                'Expected a string INTEGER payload, got %r' % (payload,))

        return asn1Spec.clone(_parseInteger(payload))


class BitStringPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        payload = self._unwrapTagged(pyObject, TAG_BITS, asn1Spec)

        if not isinstance(payload, str) or payload.strip('01'):
            raise error.PyAsn1Error(
                'Badly formed BIT STRING payload %r' % (payload,))

        return asn1Spec.clone(univ.BitString.fromBinaryString(payload))


class OctetStringPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        payload = self._unwrapTagged(pyObject, TAG_BYTES, asn1Spec)

        if not isinstance(payload, str):
            raise error.PyAsn1Error(
                'Expected a base64 string payload, got %r' % (payload,))

        try:
            octets = base64.b64decode(payload, validate=True)

        except (binascii.Error, ValueError):
            raise error.PyAsn1Error(
                'Badly formed base64 payload %r' % (payload,))

        return asn1Spec.clone(octets)


class TextStringPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        if not isinstance(pyObject, str):
            raise error.PyAsn1Error(
                'Expected a JSON string for %s, got %r' % (
                    asn1Spec.__class__.__name__, pyObject))

        return asn1Spec.clone(pyObject)


class NullPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        if pyObject is not None:
            raise error.PyAsn1Error(
                'Expected JSON null for %s, got %r' % (
                    asn1Spec.__class__.__name__, pyObject))

        return asn1Spec.clone('')


class ObjectIdentifierPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        payload = self._unwrapTagged(pyObject, TAG_OID, asn1Spec)

        if not isinstance(payload, str):
            raise error.PyAsn1Error(
                'Expected a dotted-decimal string payload, got '
                '%r' % (payload,))

        return asn1Spec.clone(payload)


class RealPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        payload = self._unwrapTagged(pyObject, TAG_REAL, asn1Spec)

        if not isinstance(payload, str):
            raise error.PyAsn1Error(
                'Expected a string REAL payload, got %r' % (payload,))

        try:
            value = float(payload)

        except ValueError:
            raise error.PyAsn1Error(
                'Badly formed REAL payload %r' % (payload,))

        if math.isnan(value):
            # pyasn1 Real cannot represent NaN
            raise error.PyAsn1Error(
                'NaN REAL payload %r is not representable' % (payload,))

        return asn1Spec.clone(value)


class SequenceOrSetPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        if not isinstance(pyObject, dict):
            raise error.PyAsn1Error(
                'Expected a JSON object for %s, got %r' % (
                    asn1Spec.__class__.__name__, pyObject))

        asn1Value = asn1Spec.clone()

        componentsTypes = asn1Value.componentType

        for field in pyObject:
            if field in ALL_TAGS or field not in componentsTypes:
                raise error.PyAsn1Error(
                    'Unexpected component %r for %s' % (
                        field, asn1Spec.__class__.__name__))

        for field in pyObject:
            asn1Value[field] = decodeFun(
                pyObject[field], componentsTypes[field].asn1Object, **options)

        return asn1Value


class SequenceOfOrSetOfPayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        if not isinstance(pyObject, list):
            raise error.PyAsn1Error(
                'Expected a JSON array for %s, got %r' % (
                    asn1Spec.__class__.__name__, pyObject))

        asn1Value = asn1Spec.clone()

        for pyValue in pyObject:
            asn1Value.append(
                decodeFun(pyValue, asn1Value.componentType, **options))

        return asn1Value


class ChoicePayloadDecoder(AbstractPayloadDecoder):
    def __call__(self, pyObject, asn1Spec, decodeFun=None, **options):
        payload = self._unwrapTagged(pyObject, TAG_CHOICE, asn1Spec)

        if not isinstance(payload, dict) or len(payload) != 1:
            raise error.PyAsn1Error(
                'Expected a single-alternative CHOICE object, got '
                '%r' % (payload,))

        asn1Value = asn1Spec.clone()

        componentsTypes = asn1Value.componentType

        for field in payload:
            if field not in componentsTypes:
                raise error.PyAsn1Error(
                    'Unknown CHOICE alternative %r for %s' % (
                        field, asn1Spec.__class__.__name__))

            asn1Value[field] = decodeFun(
                payload[field], componentsTypes[field].asn1Object, **options)

        return asn1Value


TAG_MAP = {
    univ.Integer.tagSet: IntegerPayloadDecoder(),
    univ.Boolean.tagSet: BooleanPayloadDecoder(),
    univ.BitString.tagSet: BitStringPayloadDecoder(),
    univ.OctetString.tagSet: OctetStringPayloadDecoder(),
    univ.Null.tagSet: NullPayloadDecoder(),
    univ.ObjectIdentifier.tagSet: ObjectIdentifierPayloadDecoder(),
    univ.RelativeOID.tagSet: ObjectIdentifierPayloadDecoder(),
    univ.Enumerated.tagSet: IntegerPayloadDecoder(),
    univ.Real.tagSet: RealPayloadDecoder(),
    univ.Sequence.tagSet: SequenceOrSetPayloadDecoder(),  # conflicts with SequenceOf
    univ.Set.tagSet: SequenceOrSetPayloadDecoder(),  # conflicts with SetOf
    univ.Choice.tagSet: ChoicePayloadDecoder(),  # conflicts with Any
    # character string types
    char.UTF8String.tagSet: TextStringPayloadDecoder(),
    char.NumericString.tagSet: TextStringPayloadDecoder(),
    char.PrintableString.tagSet: TextStringPayloadDecoder(),
    char.TeletexString.tagSet: TextStringPayloadDecoder(),
    char.VideotexString.tagSet: TextStringPayloadDecoder(),
    char.IA5String.tagSet: TextStringPayloadDecoder(),
    char.GraphicString.tagSet: TextStringPayloadDecoder(),
    char.VisibleString.tagSet: TextStringPayloadDecoder(),
    char.GeneralString.tagSet: TextStringPayloadDecoder(),
    char.UniversalString.tagSet: TextStringPayloadDecoder(),
    char.BMPString.tagSet: TextStringPayloadDecoder(),
    # useful types
    useful.ObjectDescriptor.tagSet: TextStringPayloadDecoder(),
    useful.GeneralizedTime.tagSet: TextStringPayloadDecoder(),
    useful.UTCTime.tagSet: TextStringPayloadDecoder()
}

# Put in ambiguous & non-ambiguous types for faster codec lookup
TYPE_MAP = {
    univ.Integer.typeId: IntegerPayloadDecoder(),
    univ.Boolean.typeId: BooleanPayloadDecoder(),
    univ.BitString.typeId: BitStringPayloadDecoder(),
    univ.OctetString.typeId: OctetStringPayloadDecoder(),
    univ.Null.typeId: NullPayloadDecoder(),
    univ.ObjectIdentifier.typeId: ObjectIdentifierPayloadDecoder(),
    univ.RelativeOID.typeId: ObjectIdentifierPayloadDecoder(),
    univ.Enumerated.typeId: IntegerPayloadDecoder(),
    univ.Real.typeId: RealPayloadDecoder(),
    # ambiguous base types
    univ.Set.typeId: SequenceOrSetPayloadDecoder(),
    univ.SetOf.typeId: SequenceOfOrSetOfPayloadDecoder(),
    univ.Sequence.typeId: SequenceOrSetPayloadDecoder(),
    univ.SequenceOf.typeId: SequenceOfOrSetOfPayloadDecoder(),
    univ.Choice.typeId: ChoicePayloadDecoder(),
    univ.Any.typeId: OctetStringPayloadDecoder(),
    # character string types
    char.UTF8String.typeId: TextStringPayloadDecoder(),
    char.NumericString.typeId: TextStringPayloadDecoder(),
    char.PrintableString.typeId: TextStringPayloadDecoder(),
    char.TeletexString.typeId: TextStringPayloadDecoder(),
    char.VideotexString.typeId: TextStringPayloadDecoder(),
    char.IA5String.typeId: TextStringPayloadDecoder(),
    char.GraphicString.typeId: TextStringPayloadDecoder(),
    char.VisibleString.typeId: TextStringPayloadDecoder(),
    char.GeneralString.typeId: TextStringPayloadDecoder(),
    char.UniversalString.typeId: TextStringPayloadDecoder(),
    char.BMPString.typeId: TextStringPayloadDecoder(),
    # useful types
    useful.ObjectDescriptor.typeId: TextStringPayloadDecoder(),
    useful.GeneralizedTime.typeId: TextStringPayloadDecoder(),
    useful.UTCTime.typeId: TextStringPayloadDecoder()
}


class SingleItemDecoder(object):

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP

    def __init__(self, tagMap=_MISSING, typeMap=_MISSING, **ignored):
        self._tagMap = tagMap if tagMap is not _MISSING else self.TAG_MAP
        self._typeMap = typeMap if typeMap is not _MISSING else self.TYPE_MAP

    def __call__(self, pyObject, asn1Spec, **options):

        if LOG:
            debug.scope.push(type(pyObject).__name__)
            LOG('decoder called at scope %s, working with '
                'type %s' % (debug.scope, type(pyObject).__name__))

        if asn1Spec is None or not isinstance(asn1Spec, base.Asn1Item):
            raise error.PyAsn1Error(
                'asn1Spec is not valid (should be an instance of an ASN.1 '
                'Item, not %s)' % asn1Spec.__class__.__name__)

        try:
            valueDecoder = self._typeMap[asn1Spec.typeId]

        except KeyError:
            # use base type for codec lookup to recover untagged types
            baseTagSet = tag.TagSet(asn1Spec.tagSet.baseTag, asn1Spec.tagSet.baseTag)

            try:
                valueDecoder = self._tagMap[baseTagSet]

            except KeyError:
                raise error.PyAsn1Error('Unknown ASN.1 tag %s' % asn1Spec.tagSet)

        if LOG:
            LOG('calling decoder %s on Python type %s '
                '<%s>' % (type(valueDecoder).__name__,
                          type(pyObject).__name__, repr(pyObject)))

        value = valueDecoder(pyObject, asn1Spec, self, **options)

        if LOG:
            LOG('decoder %s produced ASN.1 type %s '
                '<%s>' % (type(valueDecoder).__name__,
                          type(value).__name__, repr(value)))
            debug.scope.pop()

        return value


class Decoder(object):
    SINGLE_ITEM_DECODER = SingleItemDecoder

    def __init__(self, **options):
        self._singleItemDecoder = self.SINGLE_ITEM_DECODER(**options)

    def __call__(self, pyObject, asn1Spec=None, **kwargs):
        return self._singleItemDecoder(pyObject, asn1Spec=asn1Spec, **kwargs)


#: Turns JSON-safe Python objects into ASN.1 objects.
#:
#: Takes a tree of JSON-safe Python objects (as produced by
#: :py:func:`pyasn1.codec.json.encoder.encode` or parsed from a JSON
#: document) and turns it into a tree of ASN.1 objects
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative).
#:
#: The JSON document alone never determines the resulting Python
#: classes: interpretation is driven entirely by the ``asn1Spec``
#: schema, which is required. Subtype constraints carried by the
#: schema are enforced on every decoded value. Tagged objects using
#: unknown ``$``-prefixed keys, unknown SEQUENCE/SET components and
#: unknown CHOICE alternatives are rejected.
#:
#: Parameters
#: ----------
#: pyObject: :py:class:`object`
#:     A JSON-safe scalar or nested structure
#:
#: Keyword Args
#: ------------
#: asn1Spec: any pyasn1 type object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A pyasn1 type object to act as a template guiding the decoder. It is
#:     required for successful interpretation of JSON-safe objects mapping
#:     into their ASN.1 representations.
#:
#: Returns
#: -------
#: : :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A scalar or constructed pyasn1 object
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode JSON-safe Python object into ASN.1 objects with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s = decode([{'$int': '1'}, {'$int': '2'}], asn1Spec=seq)
#:    >>> str(s)
#:    SequenceOf:
#:     1 2
#:
decode = Decoder()
