#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import os
import sys

from pyasn1 import debug
from pyasn1 import error
from pyasn1.codec.ber.decoder import EOO_SENTINEL
from pyasn1.codec.ber.decoder import MAX_LENGTH_OCTETS
from pyasn1.codec.ber.decoder import MAX_NESTING_DEPTH
from pyasn1.codec.ber.decoder import MAX_TAG_OCTETS
from pyasn1.codec.ber.decoder import SingleItemDecoder
from pyasn1.codec.streaming import asSeekableStream
from pyasn1.codec.streaming import isEndOfStream
from pyasn1.codec.streaming import readFromStream
from pyasn1.type import tag
from pyasn1.type import tagmap
from pyasn1.type import univ

__all__ = ['DecodeEvent', 'EventDecoder']

LOG = debug.registerLoggee(__name__, flags=debug.DEBUG_DECODER)

SubstrateUnderrunError = error.SubstrateUnderrunError

#: Kinds of events produced by :class:`EventDecoder`
EVENT_ENTER = 'enter'
EVENT_EXIT = 'exit'
EVENT_VALUE = 'value'
EVENT_SKIP = 'skip'

#: Upper bound on a single read performed while skipping an unselected value
SKIP_CHUNK_SIZE = 65536

_RECORD_TYPE_IDS = frozenset((univ.Sequence.typeId, univ.Set.typeId))

_SEQUENCE_OF_TYPE_IDS = frozenset(
    (univ.SequenceOf.typeId, univ.SetOf.typeId))

_CONSTRUCTED_TYPE_IDS = _RECORD_TYPE_IDS | _SEQUENCE_OF_TYPE_IDS | frozenset(
    (univ.Choice.typeId,))


class DecodeEvent(object):
    """A single observation made by :class:`EventDecoder` while walking a substrate.

    Parameters
    ----------
    kind: :py:class:`str`
        One of ``enter``, ``exit``, ``value`` or ``skip``.

    path: :py:class:`tuple`
        Field path from the root ASN.1 object to the field this event
        relates to. Path components are component names of SEQUENCE/SET
        and CHOICE types and integer indices of SEQUENCE OF/SET OF items.

    offset: :py:class:`int`
        Absolute stream offset this event relates to. For ``enter``,
        ``value`` and ``skip`` events this is the offset of the first
        octet of the field encoding. For ``exit`` events this is the
        offset just past the end of the container.

    length: :py:class:`int`
        For ``enter`` events, the content length announced by the
        innermost TLV header, or -1 if indefinite. For ``exit``,
        ``value`` and ``skip`` events, the total number of octets the
        field encoding occupies.

    asn1Spec:
        The ASN.1 schema object the field was resolved against, or
        :py:class:`None` for schema-less regions.

    value:
        The decoded value for ``value`` events, :py:class:`None` otherwise.
    """
    __slots__ = ('kind', 'path', 'offset', 'length', 'asn1Spec', 'value')

    def __init__(self, kind, path, offset, length, asn1Spec=None, value=None):
        self.kind = kind
        self.path = path
        self.offset = offset
        self.length = length
        self.asn1Spec = asn1Spec
        self.value = value

    def __repr__(self):
        return '%s(kind=%r, path=%r, offset=%r, length=%r)' % (
            self.__class__.__name__, self.kind, self.path,
            self.offset, self.length)


class EventDecoder(object):
    """Walk a BER substrate schema-aware, decoding only selected fields.

    On each iteration, consume whatever BER serialization is available in
    the `substrate` stream-like object, match it against `asn1Spec` and
    report progress as :class:`DecodeEvent` objects. Fields whose path is
    listed in `select` are decoded into ASN.1 objects; everything else is
    skipped structurally, reading at most :data:`SKIP_CHUNK_SIZE` octets
    at a time, so unselected values never fully reside in memory.

    Parameters
    ----------
    substrate: :py:class:`file`, :py:class:`io.BytesIO`
        BER serialization in form of a byte stream

    Keyword Args
    ------------
    asn1Spec: :py:class:`~pyasn1.type.base.PyAsn1Item`
        A pyasn1 type object to act as a template guiding the decoder.
        Unlike :py:class:`~pyasn1.codec.ber.decoder.StreamingDecoder`,
        the schema is required here: field paths and structural skipping
        are defined in its terms.

    select: :py:class:`list`
        Field paths to decode. Each path is a tuple of component names
        (SEQUENCE/SET/CHOICE) and integer indices (SEQUENCE OF/SET OF)
        leading from the root to the wanted field; a bare string is
        treated as a single-component path. Selecting a container decodes
        the whole subtree below it. With an empty `select`, every field
        is skipped and only structural events are emitted.

    Yields
    ------
    : :py:class:`DecodeEvent`, :py:class:`~pyasn1.error.SubstrateUnderrunError`
        A ``enter``/``exit`` event pair brackets every container that
        holds selected fields somewhere below it. A ``value`` event is
        emitted for every selected field and carries the decoded object.
        A ``skip`` event is emitted for every unselected field and
        carries its offset and length, but not its value.

        :py:class:`~pyasn1.error.SubstrateUnderrunError` objects indicate
        insufficient BER serialization on input. The caller is advised to
        ensure some more data in the input stream, then call the iterator
        again. The decoder will resume the decoding process using the newly
        arrived data.

    Raises
    ------
    ~pyasn1.error.PyAsn1Error, ~pyasn1.error.EndOfStreamError
        `PyAsn1Error` on deserialization error, `EndOfStreamError` on
        premature stream closure.

    Examples
    --------
    Pick two small fields out of a message carrying a large payload

    .. code-block:: pycon

        >>> class Envelope(univ.Sequence):
        ...     componentType = namedtype.NamedTypes(
        ...         namedtype.NamedType('id', univ.Integer()),
        ...         namedtype.NamedType('payload', univ.OctetString()),
        ...         namedtype.NamedType('checksum', univ.Integer()))
        ...
        >>> decoder = EventDecoder(stream, asn1Spec=Envelope(),
        ...                        select=[('id',), ('checksum',)])
        >>> for event in decoder:
        ...     if event.kind == 'value':
        ...         print(event.path, event.value)
        ...
        ('id',) 1
        ('checksum',) 42
    """

    SINGLE_ITEM_DECODER = SingleItemDecoder

    supportIndefLength = True

    def __init__(self, substrate, asn1Spec=None, select=(), **options):
        if asn1Spec is None:
            raise error.PyAsn1Error(
                'EventDecoder requires an ASN.1 schema (asn1Spec)')

        self._singleItemDecoder = self.SINGLE_ITEM_DECODER(**options)
        self._substrate = asSeekableStream(substrate)
        self._asn1Spec = asn1Spec
        self._options = options

        selected = set()
        traverse = set()

        for path in select:
            if isinstance(path, str):
                path = (path,)
            else:
                path = tuple(path)

            selected.add(path)

            for level in range(len(path)):
                traverse.add(path[:level])

        traverse -= selected

        self._selected = frozenset(selected)
        self._traverse = frozenset(traverse)

    def __iter__(self):
        while True:
            for resolved in self._resolveSchema(
                    self._substrate, self._asn1Spec, self._options):
                if isinstance(resolved, SubstrateUnderrunError):
                    yield resolved

            chosenSpec, _, fieldEnd = resolved

            for event in self._dispatchField(
                    self._substrate, self._asn1Spec, chosenSpec, (),
                    fieldEnd, None, self._options, 0):
                yield event

            for chunk in isEndOfStream(self._substrate):
                if isinstance(chunk, SubstrateUnderrunError):
                    yield chunk

                break

            if chunk:
                break

    def _selectionState(self, path):
        if path in self._selected:
            return 'decode'

        if path in self._traverse:
            return 'traverse'

        return 'skip'

    def _dispatchField(self, substrate, spec, chosenSpec, path, fieldEnd,
                       boundary, options, depth):
        """Consume exactly one field, emitting events.

        The field starts at the current stream position. `spec` is the
        schema object (or TagMap) the field was matched against,
        `chosenSpec` the concrete schema object it resolved to (or None
        for schema-less regions), `fieldEnd` the absolute stream position
        just past the field or None if not known, `boundary` the absolute
        end of the enclosing container's content or None if unbounded.
        """
        if depth > MAX_NESTING_DEPTH:
            raise error.PyAsn1Error(
                'ASN.1 structure nesting depth exceeds limit (%d)' % (
                    MAX_NESTING_DEPTH,)
            )

        state = self._selectionState(path)

        offset = substrate.tell()

        if boundary is not None and fieldEnd is not None and fieldEnd > boundary:
            raise error.PyAsn1Error(
                'ASN.1 item at %r extends past the end of its enclosing '
                'container' % (path,))

        if state == 'decode':
            if LOG:
                LOG('decoding field at %r, offset %d' % (path, offset))

            for value in self._singleItemDecoder(
                    substrate, spec, **dict(options, _nestingLevel=depth)):
                if isinstance(value, SubstrateUnderrunError):
                    yield value

            yield DecodeEvent(
                EVENT_VALUE, path, offset, substrate.tell() - offset,
                chosenSpec, value)

        elif state == 'traverse':
            if chosenSpec is None or chosenSpec.typeId not in _CONSTRUCTED_TYPE_IDS:
                raise error.PyAsn1Error(
                    'Selection path %r does not resolve to a constructed '
                    'ASN.1 type' % (path,))

            for event in self._walkConstructed(
                    substrate, chosenSpec, path, options, depth):
                yield event

        else:
            if LOG:
                LOG('skipping field at %r, offset %d' % (path, offset))

            for underrun in self._skipValue(substrate, options, depth):
                yield underrun

            yield DecodeEvent(
                EVENT_SKIP, path, offset, substrate.tell() - offset,
                chosenSpec)

    def _walkConstructed(self, substrate, spec, path, options, depth):
        """Walk a constructed field emitting *enter* and *exit* events.

        The stream is positioned at the first octet of the field encoding
        (its outermost explicit tag, if any). Consumes the whole field.
        """
        if spec.typeId == univ.Choice.typeId and not spec.tagSet:
            # untagged CHOICE has no TLV of its own
            namedTypes = spec.clone().componentType

            if not namedTypes:
                raise error.PyAsn1Error(
                    'Choice type %r has no componentType to walk' % (spec,))

            componentTagMap = namedTypes.tagMapUnique

            offset = substrate.tell()

            for resolved in self._resolveSchema(
                    substrate, componentTagMap, options):
                if isinstance(resolved, SubstrateUnderrunError):
                    yield resolved

            chosenSpec, wireTagSet, fieldEnd = resolved

            idx = namedTypes.getPositionByType(wireTagSet)
            name = namedTypes.getNameByPosition(idx)

            if fieldEnd is None:
                enterLength = -1
            else:
                enterLength = fieldEnd - offset

            yield DecodeEvent(EVENT_ENTER, path, offset, enterLength, spec)

            for event in self._dispatchField(
                    substrate, componentTagMap, chosenSpec, path + (name,),
                    fieldEnd, None, options, depth + 1):
                yield event

            yield DecodeEvent(EVENT_EXIT, path, substrate.tell(),
                              substrate.tell() - offset, spec)

            return

        offset = substrate.tell()

        # unwrap explicit tags and the base tag, outermost first
        superTags = spec.tagSet.superTags
        headerCount = len(superTags)
        wrappers = []

        for headerIdx in range(headerCount):
            for header in self._readHeader(substrate, options):
                if isinstance(header, SubstrateUnderrunError):
                    yield header

            wireTag, length = header

            expectedTag = superTags[headerCount - 1 - headerIdx]

            if wireTag != expectedTag:
                raise error.PyAsn1Error(
                    '%s not in asn1Spec: %r' % (wireTag, spec))

            wrappers.append((length, substrate.tell()))

        contentLength, contentStart = wrappers[-1]

        if contentLength == -1:
            contentEnd = None
        else:
            contentEnd = contentStart + contentLength

        if LOG:
            LOG('walking constructed %r at %r, content length %d' % (
                spec.__class__.__name__, path, contentLength))

        yield DecodeEvent(EVENT_ENTER, path, offset, contentLength, spec)

        if spec.typeId in _RECORD_TYPE_IDS:
            for event in self._walkRecordComponents(
                    substrate, spec, path, contentEnd, options, depth):
                yield event

        elif spec.typeId in _SEQUENCE_OF_TYPE_IDS:
            for event in self._walkSequenceOfComponents(
                    substrate, spec, path, contentEnd, options, depth):
                yield event

        else:  # explicitly tagged CHOICE
            for event in self._walkChoiceComponents(
                    substrate, spec, path, contentEnd, options, depth):
                yield event

        # close explicit tag wrappers, innermost first
        for wrapperLength, wrapperStart in reversed(wrappers[:-1]):
            if wrapperLength == -1:
                for isEoo in self._probeEndOfOctets(substrate, options):
                    if isinstance(isEoo, SubstrateUnderrunError):
                        yield isEoo

                if not isEoo:
                    raise error.PyAsn1Error(
                        'Missing end-of-octets sentinel closing explicit '
                        'tag at %r' % (path,))

            elif substrate.tell() != wrapperStart + wrapperLength:
                raise error.PyAsn1Error(
                    'ASN.1 item at %r does not fill its explicit tag '
                    'wrapper' % (path,))

        yield DecodeEvent(EVENT_EXIT, path, substrate.tell(),
                          substrate.tell() - offset, spec)

    def _walkRecordComponents(self, substrate, spec, path, contentEnd,
                              options, depth):
        """Walk SEQUENCE/SET components within [tell(), contentEnd)."""
        namedTypes = spec.clone().componentType

        isSetType = spec.typeId == univ.Set.typeId
        isDeterministic = not isSetType and not namedTypes.hasOptionalOrDefault

        seenIndices = set()
        idx = 0

        while True:
            if contentEnd is not None:
                if substrate.tell() >= contentEnd:
                    break

            else:
                for isEoo in self._probeEndOfOctets(substrate, options):
                    if isinstance(isEoo, SubstrateUnderrunError):
                        yield isEoo

                if isEoo:
                    break

            if not namedTypes:
                componentSpec = None
                name = idx

            elif isSetType:
                componentSpec = namedTypes.tagMapUnique

            else:
                try:
                    if isDeterministic:
                        componentSpec = namedTypes[idx].asn1Object

                    elif (namedTypes[idx].isOptional or
                            namedTypes[idx].isDefaulted):
                        componentSpec = namedTypes.getTagMapNearPosition(idx)

                    else:
                        componentSpec = namedTypes[idx].asn1Object

                except IndexError:
                    raise error.PyAsn1Error(
                        'Excessive components decoded at %r' % (spec,))

            if componentSpec is None:
                chosenSpec = wireTagSet = fieldEnd = None

            else:
                for resolved in self._resolveSchema(
                        substrate, componentSpec, options):
                    if isinstance(resolved, SubstrateUnderrunError):
                        yield resolved

                chosenSpec, wireTagSet, fieldEnd = resolved

                if isSetType:
                    idx = namedTypes.getPositionByType(wireTagSet)

                elif not isDeterministic and (
                        namedTypes[idx].isOptional or
                        namedTypes[idx].isDefaulted):
                    idx = namedTypes.getPositionNearType(wireTagSet, idx)

                name = namedTypes.getNameByPosition(idx)

            seenIndices.add(idx)

            for event in self._dispatchField(
                    substrate, componentSpec, chosenSpec, path + (name,),
                    fieldEnd, contentEnd, options, depth + 1):
                yield event

            if contentEnd is not None and substrate.tell() > contentEnd:
                raise error.PyAsn1Error(
                    'ASN.1 item at %r extends past the end of its '
                    'enclosing container' % (path + (name,),))

            idx += 1

        if namedTypes:
            if not namedTypes.requiredComponents.issubset(seenIndices):
                raise error.PyAsn1Error(
                    'ASN.1 object %s has uninitialized '
                    'components' % spec.__class__.__name__)

    def _walkSequenceOfComponents(self, substrate, spec, path, contentEnd,
                                  options, depth):
        """Walk SEQUENCE OF/SET OF items within [tell(), contentEnd)."""
        componentSpec = spec.clone().componentType

        idx = 0

        while True:
            if contentEnd is not None:
                if substrate.tell() >= contentEnd:
                    break

            else:
                for isEoo in self._probeEndOfOctets(substrate, options):
                    if isinstance(isEoo, SubstrateUnderrunError):
                        yield isEoo

                if isEoo:
                    break

            if componentSpec is None:
                chosenSpec = fieldEnd = None

            else:
                for resolved in self._resolveSchema(
                        substrate, componentSpec, options):
                    if isinstance(resolved, SubstrateUnderrunError):
                        yield resolved

                chosenSpec, _, fieldEnd = resolved

            for event in self._dispatchField(
                    substrate, componentSpec, chosenSpec, path + (idx,),
                    fieldEnd, contentEnd, options, depth + 1):
                yield event

            if contentEnd is not None and substrate.tell() > contentEnd:
                raise error.PyAsn1Error(
                    'ASN.1 item at %r extends past the end of its '
                    'enclosing container' % (path + (idx,),))

            idx += 1

    def _walkChoiceComponents(self, substrate, spec, path, contentEnd,
                              options, depth):
        """Walk the alternative(s) of an explicitly tagged CHOICE."""
        namedTypes = spec.clone().componentType

        if not namedTypes:
            raise error.PyAsn1Error(
                'Choice type %r has no componentType to walk' % (spec,))

        componentTagMap = namedTypes.tagMapUnique

        if contentEnd is not None:
            # definite-length explicit CHOICE holds exactly one alternative
            for event in self._walkChoiceAlternative(
                    substrate, namedTypes, componentTagMap, path,
                    contentEnd, options, depth):
                yield event

            if substrate.tell() != contentEnd:
                raise error.PyAsn1Error(
                    'ASN.1 item at %r does not fill its enclosing '
                    'container' % (path,))

        else:
            while True:
                for isEoo in self._probeEndOfOctets(substrate, options):
                    if isinstance(isEoo, SubstrateUnderrunError):
                        yield isEoo

                if isEoo:
                    break

                for event in self._walkChoiceAlternative(
                        substrate, namedTypes, componentTagMap, path,
                        None, options, depth):
                    yield event

    def _walkChoiceAlternative(self, substrate, namedTypes, componentTagMap,
                               path, boundary, options, depth):
        """Resolve and walk one CHOICE alternative."""
        for resolved in self._resolveSchema(substrate, componentTagMap, options):
            if isinstance(resolved, SubstrateUnderrunError):
                yield resolved

        chosenSpec, wireTagSet, fieldEnd = resolved

        idx = namedTypes.getPositionByType(wireTagSet)
        name = namedTypes.getNameByPosition(idx)

        for event in self._dispatchField(
                substrate, componentTagMap, chosenSpec, path + (name,),
                fieldEnd, boundary, options, depth + 1):
            yield event

    def _skipValue(self, substrate, options, depth):
        """Consume one TLV without materializing its value.

        Yields SubstrateUnderrunError sentinels only. Definite-length
        content is discarded in chunks of at most SKIP_CHUNK_SIZE octets;
        indefinite-length content is walked TLV by TLV down to the
        matching end-of-octets sentinel.
        """
        if depth > MAX_NESTING_DEPTH:
            raise error.PyAsn1Error(
                'ASN.1 structure nesting depth exceeds limit (%d)' % (
                    MAX_NESTING_DEPTH,)
            )

        for header in self._readHeader(substrate, options):
            if isinstance(header, SubstrateUnderrunError):
                yield header

        _, length = header

        if length == -1:
            while True:
                for isEoo in self._probeEndOfOctets(substrate, options):
                    if isinstance(isEoo, SubstrateUnderrunError):
                        yield isEoo

                if isEoo:
                    break

                for underrun in self._skipValue(substrate, options, depth + 1):
                    yield underrun

        else:
            remaining = length

            while remaining > 0:
                chunkSize = min(remaining, SKIP_CHUNK_SIZE)

                for chunk in readFromStream(substrate, chunkSize, options):
                    if isinstance(chunk, SubstrateUnderrunError):
                        yield chunk

                remaining -= chunkSize

    def _resolveSchema(self, substrate, spec, options):
        """Read just enough TLV headers to resolve `spec` against the wire.

        Explicit tag wrappers are peeked through. The stream position is
        restored before returning, so the caller can re-dispatch on the
        resolved schema. The last value yielded is a (chosenSpec,
        wireTagSet, fieldEnd) tuple, where fieldEnd is the absolute
        stream position just past the field or None if the outermost
        header is indefinite-length.
        """
        offset = substrate.tell()

        wireTagSet = tag.TagSet()
        fieldEnd = None
        firstHeader = True

        try:
            while True:
                for header in self._readHeader(substrate, options):
                    if isinstance(header, SubstrateUnderrunError):
                        yield header

                wireTag, length = header

                if firstHeader:
                    if length >= 0:
                        fieldEnd = substrate.tell() + length

                    firstHeader = False

                wireTagSet = wireTag + wireTagSet

                chosenSpec = self._lookupSchema(spec, wireTagSet)

                if chosenSpec is not None:
                    break

                if (wireTag.tagFormat == tag.tagFormatConstructed and
                        wireTag.tagClass != tag.tagClassUniversal):
                    # assume explicit tagging, look one level deeper
                    continue

                raise error.PyAsn1Error(
                    '%s not in asn1Spec: %r' % (wireTagSet, spec))

        finally:
            substrate.seek(offset)

        yield chosenSpec, wireTagSet, fieldEnd

    @staticmethod
    def _lookupSchema(spec, wireTagSet):
        if isinstance(spec, tagmap.TagMap):
            try:
                return spec[wireTagSet]

            except KeyError:
                return None

        if wireTagSet == spec.tagSet or wireTagSet in spec.tagMap:
            return spec

        return None

    def _readHeader(self, substrate, options):
        """Read a BER TLV header.

        The last value yielded is a (tag, length) tuple, where length
        of -1 means indefinite.
        """
        for firstByte in readFromStream(substrate, 1, options):
            if isinstance(firstByte, SubstrateUnderrunError):
                yield firstByte

        firstOctet = ord(firstByte)

        tagClass = firstOctet & 0xC0
        tagFormat = firstOctet & 0x20
        tagId = firstOctet & 0x1F

        if tagId == 0x1F:
            tagOctetCount = 0
            tagId = 0

            while True:
                for integerByte in readFromStream(substrate, 1, options):
                    if isinstance(integerByte, SubstrateUnderrunError):
                        yield integerByte

                if not integerByte:
                    raise error.SubstrateUnderrunError(
                        'Short octet stream on long tag decoding')

                integerTag = ord(integerByte)
                tagOctetCount += 1
                if tagOctetCount > MAX_TAG_OCTETS:
                    raise error.PyAsn1Error(
                        'Tag ID octet count exceeds limit (%d)' % (
                            MAX_TAG_OCTETS,))
                tagId <<= 7
                tagId |= (integerTag & 0x7F)

                if not integerTag & 0x80:
                    break

        wireTag = tag.Tag(
            tagClass=tagClass, tagFormat=tagFormat, tagId=tagId)

        for firstOctet in readFromStream(substrate, 1, options):
            if isinstance(firstOctet, SubstrateUnderrunError):
                yield firstOctet

        firstOctet = ord(firstOctet)

        if firstOctet < 128:
            length = firstOctet

        elif firstOctet > 128:
            size = firstOctet & 0x7F

            if size > MAX_LENGTH_OCTETS:
                raise error.PyAsn1Error(
                    'BER length field size %d exceeds limit (%d)' % (
                        size, MAX_LENGTH_OCTETS))

            for encodedLength in readFromStream(substrate, size, options):
                if isinstance(encodedLength, SubstrateUnderrunError):
                    yield encodedLength
            encodedLength = list(encodedLength)
            if len(encodedLength) != size:
                raise error.SubstrateUnderrunError(
                    '%s<%s at %s' % (size, len(encodedLength), wireTag))

            length = 0
            for lengthOctet in encodedLength:
                length <<= 8
                length |= lengthOctet

            if length > sys.maxsize:
                raise error.PyAsn1Error(
                    'Length %d exceeds maximum readable size %d' % (
                        length, sys.maxsize))

        else:  # 128 means indefinite
            if not self.supportIndefLength:
                raise error.PyAsn1Error(
                    'Indefinite length encoding not supported by this codec')

            length = -1

        yield wireTag, length

    def _probeEndOfOctets(self, substrate, options):
        """Consume and report end-of-octets sentinel, if it follows.

        The last value yielded is True if the EOC sentinel was found
        (and consumed), False otherwise (stream position restored).
        """
        for eooCandidate in readFromStream(substrate, 2, options):
            if isinstance(eooCandidate, SubstrateUnderrunError):
                yield eooCandidate

        if eooCandidate == EOO_SENTINEL:
            yield True

        else:
            substrate.seek(-2, os.SEEK_CUR)
            yield False
