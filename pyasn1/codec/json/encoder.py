#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
from collections import OrderedDict
import json
import math
import warnings

from pyasn1 import debug
from pyasn1 import error
from pyasn1.compat import _MISSING
from pyasn1.type import base
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

__all__ = ['encode', 'dumps']

LOG = debug.registerLoggee(__name__, flags=debug.DEBUG_ENCODER)

#: Reserved JSON object keys tagging values that JSON can not
#: express natively. A business SEQUENCE/SET maps to a plain JSON
#: object keyed by field name, so these ``__*__`` keys never appear
#: at a position where the schema expects a constructed type, and
#: the schema-driven decoder can not confuse them with field names.
TAG_INT = '__int__'
TAG_BYTES = '__bytes__'
TAG_BITS = '__bits__'
TAG_OID = '__oid__'
TAG_ROID = '__roid__'
TAG_REAL = '__real__'
TAG_CHOICE = '__choice__'

RESERVED_TAGS = frozenset(
    [TAG_INT, TAG_BYTES, TAG_BITS, TAG_OID, TAG_ROID, TAG_REAL, TAG_CHOICE]
)


class AbstractItemEncoder(object):
    def encode(self, value, encodeFun, **options):
        raise error.PyAsn1Error('Not implemented')


class BooleanEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return bool(value)


class IntegerEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        try:
            return {TAG_INT: str(int(value))}

        except ValueError as exc:
            # Python 3.11+ int->str conversion limit
            raise error.PyAsn1Error(
                'INTEGER value too large to serialize: %s' % (exc,))


class BitStringEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_BITS: {
            'length': len(value),
            'data': value.asOctets().hex()
        }}


class OctetStringEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_BYTES: value.asOctets().hex()}


class TextStringEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return str(value)


class NullEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return None


class ObjectIdentifierEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_OID: str(value)}


class RelativeOIDEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_ROID: str(value)}


class RealEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        floatValue = float(value)

        if math.isnan(floatValue):
            return {TAG_REAL: 'NaN'}
        elif math.isinf(floatValue):
            return {TAG_REAL: floatValue > 0 and 'Infinity' or '-Infinity'}
        else:
            return floatValue


class SetEncoder(AbstractItemEncoder):
    protoDict = dict

    def encode(self, value, encodeFun, **options):
        inconsistency = value.isInconsistent
        if inconsistency:
            raise error.PyAsn1Error(
                f"ASN.1 object {value.__class__.__name__} is inconsistent")

        namedTypes = value.componentType
        substrate = self.protoDict()

        for idx in range(value._componentTypeLen or len(value._dynamicNames)):
            if namedTypes:
                namedType = namedTypes[idx]
                key = namedType.name
                subValue = value.getComponentByPosition(idx, instantiate=False)

                if subValue is univ.noValue:
                    # Absent OPTIONAL/DEFAULT components stay absent so
                    # that a decode round-trip preserves their state
                    continue

            else:
                key = value._dynamicNames.getNameByPosition(idx)
                subValue = value.getComponentByPosition(idx, instantiate=False)

            substrate[key] = encodeFun(subValue, **options)
        return substrate


class SequenceEncoder(SetEncoder):
    protoDict = OrderedDict


class SequenceOfEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        inconsistency = value.isInconsistent
        if inconsistency:
            raise error.PyAsn1Error(
                f"ASN.1 object {value.__class__.__name__} is inconsistent")
        return [encodeFun(x, **options) for x in value]


class ChoiceEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        inconsistency = value.isInconsistent
        if inconsistency:
            raise error.PyAsn1Error(
                f"ASN.1 object {value.__class__.__name__} is inconsistent")

        return {TAG_CHOICE: {
            'name': value.getName(),
            'value': encodeFun(value.getComponent(), **options)
        }}


class AnyEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_BYTES: value.asOctets().hex()}


TAG_MAP = {
    univ.Boolean.tagSet: BooleanEncoder(),
    univ.Integer.tagSet: IntegerEncoder(),
    univ.BitString.tagSet: BitStringEncoder(),
    univ.OctetString.tagSet: OctetStringEncoder(),
    univ.Null.tagSet: NullEncoder(),
    univ.ObjectIdentifier.tagSet: ObjectIdentifierEncoder(),
    univ.RelativeOID.tagSet: RelativeOIDEncoder(),
    univ.Enumerated.tagSet: IntegerEncoder(),
    univ.Real.tagSet: RealEncoder(),
    # Sequence & Set have same tags as SequenceOf & SetOf
    univ.SequenceOf.tagSet: SequenceOfEncoder(),
    univ.SetOf.tagSet: SequenceOfEncoder(),
    univ.Choice.tagSet: ChoiceEncoder(),
    # character string types
    char.UTF8String.tagSet: TextStringEncoder(),
    char.NumericString.tagSet: TextStringEncoder(),
    char.PrintableString.tagSet: TextStringEncoder(),
    char.TeletexString.tagSet: TextStringEncoder(),
    char.VideotexString.tagSet: TextStringEncoder(),
    char.IA5String.tagSet: TextStringEncoder(),
    char.GraphicString.tagSet: TextStringEncoder(),
    char.VisibleString.tagSet: TextStringEncoder(),
    char.GeneralString.tagSet: TextStringEncoder(),
    char.UniversalString.tagSet: TextStringEncoder(),
    char.BMPString.tagSet: TextStringEncoder(),
    # useful types
    useful.ObjectDescriptor.tagSet: TextStringEncoder(),
    useful.GeneralizedTime.tagSet: TextStringEncoder(),
    useful.UTCTime.tagSet: TextStringEncoder()
}

# Put in ambiguous & non-ambiguous types for faster codec lookup
TYPE_MAP = {
    univ.Boolean.typeId: BooleanEncoder(),
    univ.Integer.typeId: IntegerEncoder(),
    univ.BitString.typeId: BitStringEncoder(),
    univ.OctetString.typeId: OctetStringEncoder(),
    univ.Null.typeId: NullEncoder(),
    univ.ObjectIdentifier.typeId: ObjectIdentifierEncoder(),
    univ.RelativeOID.typeId: RelativeOIDEncoder(),
    univ.Enumerated.typeId: IntegerEncoder(),
    univ.Real.typeId: RealEncoder(),
    # Sequence & Set have same tags as SequenceOf & SetOf
    univ.Set.typeId: SetEncoder(),
    univ.SetOf.typeId: SequenceOfEncoder(),
    univ.Sequence.typeId: SequenceEncoder(),
    univ.SequenceOf.typeId: SequenceOfEncoder(),
    univ.Choice.typeId: ChoiceEncoder(),
    univ.Any.typeId: AnyEncoder(),
    # character string types
    char.UTF8String.typeId: TextStringEncoder(),
    char.NumericString.typeId: TextStringEncoder(),
    char.PrintableString.typeId: TextStringEncoder(),
    char.TeletexString.typeId: TextStringEncoder(),
    char.VideotexString.typeId: TextStringEncoder(),
    char.IA5String.typeId: TextStringEncoder(),
    char.GraphicString.typeId: TextStringEncoder(),
    char.VisibleString.typeId: TextStringEncoder(),
    char.GeneralString.typeId: TextStringEncoder(),
    char.UniversalString.typeId: TextStringEncoder(),
    char.BMPString.typeId: TextStringEncoder(),
    # useful types
    useful.ObjectDescriptor.typeId: TextStringEncoder(),
    useful.GeneralizedTime.typeId: TextStringEncoder(),
    useful.UTCTime.typeId: TextStringEncoder()
}


class SingleItemEncoder(object):

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP

    def __init__(self, tagMap=_MISSING, typeMap=_MISSING, **ignored):
        self._tagMap = tagMap if tagMap is not _MISSING else self.TAG_MAP
        self._typeMap = typeMap if typeMap is not _MISSING else self.TYPE_MAP

    def __call__(self, value, **options):
        if not isinstance(value, base.Asn1Item):
            raise error.PyAsn1Error(
                'value is not valid (should be an instance of an ASN.1 Item)')

        if LOG:
            debug.scope.push(type(value).__name__)
            LOG('encoder called for type %s '
                '<%s>' % (type(value).__name__, value.prettyPrint()))

        tagSet = value.tagSet

        try:
            concreteEncoder = self._typeMap[value.typeId]

        except KeyError:
            # use base type for codec lookup to recover untagged types
            baseTagSet = tag.TagSet(
                value.tagSet.baseTag, value.tagSet.baseTag)

            try:
                concreteEncoder = self._tagMap[baseTagSet]

            except KeyError:
                raise error.PyAsn1Error('No encoder for %s' % (value,))

        if LOG:
            LOG('using value codec %s chosen by '
                '%s' % (concreteEncoder.__class__.__name__, tagSet))

        pyObject = concreteEncoder.encode(value, self, **options)

        if LOG:
            LOG('encoder %s produced: '
                '%s' % (type(concreteEncoder).__name__, repr(pyObject)))
            debug.scope.pop()

        return pyObject


class Encoder(object):
    SINGLE_ITEM_ENCODER = SingleItemEncoder

    def __init__(self, **options):
        self._singleItemEncoder = self.SINGLE_ITEM_ENCODER(**options)

    def __call__(self, pyObject, asn1Spec=None, **options):
        return self._singleItemEncoder(
            pyObject, asn1Spec=asn1Spec, **options)


#: Turns ASN.1 object into a JSON-safe Python object(s).
#:
#: Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item`
#: derivative), walks all its components recursively and produces a tree
#: made exclusively of JSON-safe Python types: :py:class:`dict`,
#: :py:class:`list`, :py:class:`str`, :py:class:`float`, :py:class:`bool`
#: and :py:obj:`None`. Unlike the ``native`` codec, values that JSON can
#: not express natively are wrapped into single-key objects carrying a
#: reserved tag:
#:
#: * ``INTEGER``/``ENUMERATED`` -> ``{"__int__": "<decimal>"}``
#: * ``OCTET STRING``/``ANY`` -> ``{"__bytes__": "<hex>"}``
#: * ``BIT STRING`` -> ``{"__bits__": {"length": <bits>, "data": "<hex>"}}``
#: * ``OBJECT IDENTIFIER`` -> ``{"__oid__": "<dotted>"}``
#: * ``RELATIVE-OID`` -> ``{"__roid__": "<dotted>"}``
#: * non-finite ``REAL`` -> ``{"__real__": "Infinity"|"-Infinity"|"NaN"}``
#: * ``CHOICE`` -> ``{"__choice__": {"name": <field>, "value": <value>}}``
#:
#: ``SEQUENCE``/``SET`` map to plain JSON objects keyed by field name;
#: absent OPTIONAL and DEFAULT components are omitted, so a decode
#: round-trip preserves their absence. ``SEQUENCE OF``/``SET OF`` map
#: to JSON arrays. Booleans, nulls, finite reals and character strings
#: map to their natural JSON counterparts.
#:
#: Parameters
#: ----------
#  asn1Value: any pyasn1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     pyasn1 object to encode (or a tree of them)
#:
#: Returns
#: -------
#: : :py:class:`object`
#:     JSON-safe Python object (or a tree of them)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error
#:     On encoding errors
#:
#: Examples
#: --------
#: Encode ASN.1 value object into a JSON-safe tree
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> seq.extend([1, 2, 3])
#:    >>> encode(seq)
#:    [{'__int__': '1'}, {'__int__': '2'}, {'__int__': '3'}]
#:
encode = SingleItemEncoder()


def dumps(value, **options):
    """Encode ASN.1 value into canonical JSON text.

    The output is deterministic: object keys are sorted and the
    separators are compact, so encoding the same value twice yields
    byte-identical text.

    Parameters
    ----------
    value: any pyasn1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
        pyasn1 object to encode

    Returns
    -------
    : :py:class:`str`
        Canonical JSON text
    """
    return json.dumps(
        encode(value, **options), sort_keys=True, separators=(',', ':'))


def __getattr__(attr: str):
    if newAttr := {"tagMap": "TAG_MAP", "typeMap": "TYPE_MAP"}.get(attr):
        warnings.warn(f"{attr} is deprecated. Please use {newAttr} instead.", DeprecationWarning, stacklevel=2)
        return globals()[newAttr]
    raise AttributeError(attr)
