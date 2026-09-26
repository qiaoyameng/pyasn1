#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
from collections import OrderedDict
import base64

from pyasn1 import debug
from pyasn1 import error
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

__all__ = ['encode']

LOG = debug.registerLoggee(__name__, flags=debug.DEBUG_ENCODER)


def _renderInteger(value):
    # Decimal rendering of a huge integer can exceed the interpreter's
    # integer-to-string conversion limit (sys.get_int_max_str_digits(),
    # Python 3.11+) and raise ValueError; hexadecimal is not limited
    try:
        return str(value)

    except ValueError:
        return hex(value)


class AbstractItemEncoder(object):
    def encode(self, value, encodeFun, **options):
        raise error.PyAsn1Error('Not implemented')


class BooleanEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return bool(value)


class IntegerEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_INTEGER: _renderInteger(int(value))}


class BitStringEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        # str() of a zero-length BitString is '0', not ''
        if len(value):
            binString = str(value)
        else:
            binString = ''
        return {TAG_BITS: binString}


class OctetStringEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_BYTES: base64.b64encode(value.asOctets()).decode('ascii')}


class TextStringEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return str(value)


class NullEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return None


class ObjectIdentifierEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_OID: str(value)}


class RealEncoder(AbstractItemEncoder):
    def encode(self, value, encodeFun, **options):
        return {TAG_REAL: repr(float(value))}


class SetEncoder(AbstractItemEncoder):
    protoDict = OrderedDict

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
                    if namedType.isOptional or namedType.isDefaulted:
                        # absent components stay absent: the format
                        # expresses them as missing object keys
                        continue
                    else:
                        raise error.PyAsn1Error(
                            f"Mandatory component {key!r} of "
                            f"{value.__class__.__name__} is not set")

            else:
                key = value._dynamicNames.getNameByPosition(idx)
                subValue = value.getComponentByPosition(idx, instantiate=False)

            substrate[key] = encodeFun(subValue, **options)
        return substrate


class SequenceEncoder(SetEncoder):
    pass


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

        for key, subValue in value.items():
            return {TAG_CHOICE: {key: encodeFun(subValue, **options)}}

        raise error.PyAsn1Error(
            f"ASN.1 CHOICE object {value.__class__.__name__} has no "
            f"alternative chosen")


class AnyEncoder(OctetStringEncoder):
    pass


TAG_MAP = {
    univ.Boolean.tagSet: BooleanEncoder(),
    univ.Integer.tagSet: IntegerEncoder(),
    univ.BitString.tagSet: BitStringEncoder(),
    univ.OctetString.tagSet: OctetStringEncoder(),
    univ.Null.tagSet: NullEncoder(),
    univ.ObjectIdentifier.tagSet: ObjectIdentifierEncoder(),
    univ.RelativeOID.tagSet: ObjectIdentifierEncoder(),
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
    univ.RelativeOID.typeId: ObjectIdentifierEncoder(),
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
#: Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#: walks all its components recursively and produces a tree composed
#: exclusively of JSON-safe Python types: :py:class:`dict`,
#: :py:class:`list`, :py:class:`str`, :py:class:`bool` and
#: :py:class:`None`. Values that JSON scalars cannot express losslessly
#: (arbitrary-precision integers, octets, bit strings, object
#: identifiers, reals, the chosen CHOICE alternative) are wrapped into
#: single-key *tagged* objects whose keys are defined in
#: :py:mod:`pyasn1.codec.json` (e.g. ``{'$int': '123'}``). Tag names
#: start with ``$`` so they can never collide with ASN.1 component
#: names.
#:
#: The output is canonical: encoding the same value twice yields equal
#: trees, and serialising with ``json.dumps(tree, sort_keys=True)``
#: produces a stable document. Absent OPTIONAL and DEFAULT components
#: of SEQUENCE/SET are omitted from the resulting object rather than
#: materialised.
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
#: Encode ASN.1 value object into JSON-safe Python types
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> seq.extend([1, 2, 3])
#:    >>> encode(seq)
#:    [{'$int': '1'}, {'$int': '2'}, {'$int': '3'}]
#:
encode = SingleItemEncoder()
