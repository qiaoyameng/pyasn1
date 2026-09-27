#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import warnings

from pyasn1 import debug
from pyasn1 import error
from pyasn1.codec.ber import eoo
from pyasn1.compat import _MISSING
from pyasn1.compat.integer import to_bytes
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

__all__ = ['Encoder', 'encode', 'iterencode']

LOG = debug.registerLoggee(__name__, flags=debug.DEBUG_ENCODER)


class AbstractItemEncoder(object):
    supportIndefLenMode = True

    # An outcome of otherwise legit call `encodeFun(eoo.endOfOctets)`
    eooIntegerSubstrate = (0, 0)
    eooOctetsSubstrate = bytes(eooIntegerSubstrate)

    # noinspection PyMethodMayBeStatic
    def encodeTag(self, singleTag, isConstructed):
        tagClass, tagFormat, tagId = singleTag
        encodedTag = tagClass | tagFormat
        if isConstructed:
            encodedTag |= tag.tagFormatConstructed

        if tagId < 31:
            return encodedTag | tagId,

        else:
            substrate = tagId & 0x7f,

            tagId >>= 7

            while tagId:
                substrate = (0x80 | (tagId & 0x7f),) + substrate
                tagId >>= 7

            return (encodedTag | 0x1F,) + substrate

    def encodeLength(self, length, defMode):
        if not defMode and self.supportIndefLenMode:
            return (0x80,)

        if length < 0x80:
            return length,

        else:
            substrate = ()
            while length:
                substrate = (length & 0xff,) + substrate
                length >>= 8

            substrateLen = len(substrate)

            if substrateLen > 126:
                raise error.PyAsn1Error('Length octets overflow (%d)' % substrateLen)

            return (0x80 | substrateLen,) + substrate

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        raise error.PyAsn1Error('Not implemented')

    def computeValueLength(self, value, asn1Spec, encodeFun, **options):
        """Compute the number of content octets the value encodes into.

        The default implementation encodes the value and measures the
        substrate; types with potentially large payloads override it
        with direct length arithmetic to avoid materializing the
        encoded value.
        """
        substrate, _, _ = self.encodeValue(value, asn1Spec, encodeFun, **options)
        return len(substrate)

    def computeOctetsLength(self, octetsLength, asn1Spec, encodeFun, **options):
        raise error.PyAsn1Error('Not implemented')

    def isConstructedEncoding(self, value, asn1Spec, **options):
        return False

    def iterEncodeValue(self, value, asn1Spec, encodeFun, **options):
        substrate, _, _ = self.encodeValue(value, asn1Spec, encodeFun, **options)
        if substrate:
            yield bytes(substrate)

    def encode(self, value, asn1Spec=None, encodeFun=None, **options):

        if asn1Spec is None:
            tagSet = value.tagSet
        else:
            tagSet = asn1Spec.tagSet

        # untagged item?
        if not tagSet:
            substrate, isConstructed, isOctets = self.encodeValue(
                value, asn1Spec, encodeFun, **options
            )
            return substrate

        defMode = options.get('defMode', True)

        substrate = b''

        for idx, singleTag in enumerate(tagSet.superTags):

            defModeOverride = defMode

            # base tag?
            if not idx:
                try:
                    substrate, isConstructed, isOctets = self.encodeValue(
                        value, asn1Spec, encodeFun, **options
                    )

                except error.PyAsn1Error as exc:
                    raise error.PyAsn1Error(
                        'Error encoding %r: %s' % (value, exc))

                if LOG:
                    LOG('encoded %svalue %s into %s' % (
                        isConstructed and 'constructed ' or '', value, substrate
                    ))

                if not substrate and isConstructed and options.get('ifNotEmpty', False):
                    return substrate

                if not isConstructed:
                    defModeOverride = True

                    if LOG:
                        LOG('overridden encoding mode into definitive for primitive type')

            header = self.encodeTag(singleTag, isConstructed)

            if LOG:
                LOG('encoded %stag %s into %s' % (
                    isConstructed and 'constructed ' or '',
                    singleTag, debug.hexdump(bytes(header))))

            header += self.encodeLength(len(substrate), defModeOverride)

            if LOG:
                LOG('encoded %s octets (tag + payload) into %s' % (
                    len(substrate), debug.hexdump(bytes(header))))

            if isOctets:
                substrate = bytes(header) + substrate

                if not defModeOverride:
                    substrate += self.eooOctetsSubstrate

            else:
                substrate = header + substrate

                if not defModeOverride:
                    substrate += self.eooIntegerSubstrate

        if not isOctets:
            substrate = bytes(substrate)

        return substrate

    def _frameHeaders(self, contentLength, isConstructed, tagSet, defMode):
        """Compute (header, trailer) octets for every tag layer.

        Returns a list of (header, trailer) pairs, innermost tag first,
        mirroring the framing that `encode` applies to the substrate.
        """
        layers = []

        length = contentLength

        for idx, singleTag in enumerate(tagSet.superTags):

            defModeOverride = defMode

            # base tag?
            if not idx and not isConstructed:
                defModeOverride = True

            header = self.encodeTag(singleTag, isConstructed)
            header += self.encodeLength(length, defModeOverride)
            header = bytes(header)

            if defModeOverride:
                trailer = b''
            else:
                trailer = self.eooOctetsSubstrate

            layers.append((header, trailer))

            length += len(header) + len(trailer)

        return layers

    def computeLength(self, value, asn1Spec, encodeFun, **options):
        """Compute the number of octets the value encodes into.

        Mirrors `encode` framing without building the substrate.
        """
        if asn1Spec is None:
            tagSet = value.tagSet
        else:
            tagSet = asn1Spec.tagSet

        # untagged item?
        if not tagSet:
            return self.computeValueLength(
                value, asn1Spec, encodeFun, **options)

        try:
            contentLength = self.computeValueLength(
                value, asn1Spec, encodeFun, **options)

        except error.PyAsn1Error as exc:
            raise error.PyAsn1Error(
                'Error encoding %r: %s' % (value, exc))

        isConstructed = self.isConstructedEncoding(value, asn1Spec, **options)

        if (not contentLength and isConstructed and
                options.get('ifNotEmpty', False)):
            return 0

        layers = self._frameHeaders(
            contentLength, isConstructed, tagSet,
            options.get('defMode', True))

        return contentLength + sum(
            len(header) + len(trailer) for header, trailer in layers)

    def iterEncode(self, value, asn1Spec, encodeFun, **options):
        """Encode the value, yielding substrate chunks as they are produced.

        Definite-length framing requires the content length up front, so
        it is precomputed (without building the substrate) before the
        first chunk is yielded. Indefinite-length framing needs no
        precomputation and streams right away.
        """
        if asn1Spec is None:
            tagSet = value.tagSet
        else:
            tagSet = asn1Spec.tagSet

        # untagged item?
        if not tagSet:
            for chunk in self.iterEncodeValue(
                    value, asn1Spec, encodeFun, **options):
                yield chunk
            return

        defMode = options.get('defMode', True)

        isConstructed = self.isConstructedEncoding(value, asn1Spec, **options)

        if defMode or not isConstructed or options.get('ifNotEmpty', False):
            try:
                contentLength = self.computeValueLength(
                    value, asn1Spec, encodeFun, **options)

            except error.PyAsn1Error as exc:
                raise error.PyAsn1Error(
                    'Error encoding %r: %s' % (value, exc))

            if (not contentLength and isConstructed and
                    options.get('ifNotEmpty', False)):
                return

        else:
            # indefinite framing needs no content length
            contentLength = 0

        layers = self._frameHeaders(
            contentLength, isConstructed, tagSet, defMode)

        if LOG:
            LOG('encoding %svalue of type %s into %s tag layer(s)' % (
                isConstructed and 'constructed ' or '',
                value.__class__.__name__, len(layers)))

        for header, trailer in reversed(layers):
            yield header

        try:
            for chunk in self.iterEncodeValue(
                    value, asn1Spec, encodeFun, **options):
                yield chunk

        except error.PyAsn1Error as exc:
            raise error.PyAsn1Error(
                'Error encoding %r: %s' % (value, exc))

        for header, trailer in layers:
            if trailer:
                yield trailer


class EndOfOctetsEncoder(AbstractItemEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        return b'', False, True


class BooleanEncoder(AbstractItemEncoder):
    supportIndefLenMode = False

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        return value and (1,) or (0,), False, False


class IntegerEncoder(AbstractItemEncoder):
    supportIndefLenMode = False
    supportCompactZero = False

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        if value == 0:
            if LOG:
                LOG('encoding %spayload for zero INTEGER' % (
                    self.supportCompactZero and 'no ' or ''
                ))

            # de-facto way to encode zero
            if self.supportCompactZero:
                return (), False, False
            else:
                return (0,), False, False

        return to_bytes(int(value), signed=True), False, True


class BitStringEncoder(AbstractItemEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is not None:
            # TODO: try to avoid ASN.1 schema instantiation
            value = asn1Spec.clone(value)

        valueLength = len(value)
        if valueLength % 8:
            alignedValue = value << (8 - valueLength % 8)
        else:
            alignedValue = value

        maxChunkSize = options.get('maxChunkSize', 0)
        if not maxChunkSize or len(alignedValue) <= maxChunkSize * 8:
            substrate = alignedValue.asOctets()
            return bytes((len(substrate) * 8 - valueLength,)) + substrate, False, True

        if LOG:
            LOG('encoding into up to %s-octet chunks' % maxChunkSize)

        baseTag = value.tagSet.baseTag

        # strip off explicit tags
        if baseTag:
            tagSet = tag.TagSet(baseTag, baseTag)

        else:
            tagSet = tag.TagSet()

        alignedValue = alignedValue.clone(tagSet=tagSet)

        stop = 0
        substrate = b''
        while stop < valueLength:
            start = stop
            stop = min(start + maxChunkSize * 8, valueLength)
            substrate += encodeFun(alignedValue[start:stop], asn1Spec, **options)

        return substrate, True, True

    def isConstructedEncoding(self, value, asn1Spec, **options):
        maxChunkSize = options.get('maxChunkSize', 0)
        if not maxChunkSize:
            return False

        if asn1Spec is not None:
            value = asn1Spec.clone(value)

        valueLength = len(value)
        if valueLength % 8:
            valueLength += 8 - valueLength % 8

        return valueLength > maxChunkSize * 8

    def computeValueLength(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is not None:
            # TODO: try to avoid ASN.1 schema instantiation
            value = asn1Spec.clone(value)

        valueLength = len(value)
        if valueLength % 8:
            alignedValue = value << (8 - valueLength % 8)
        else:
            alignedValue = value

        maxChunkSize = options.get('maxChunkSize', 0)
        if not maxChunkSize or len(alignedValue) <= maxChunkSize * 8:
            return 1 + (len(alignedValue) + 7) // 8

        baseTag = value.tagSet.baseTag

        # strip off explicit tags
        if baseTag:
            tagSet = tag.TagSet(baseTag, baseTag)

        else:
            tagSet = tag.TagSet()

        alignedValue = alignedValue.clone(tagSet=tagSet)

        stop = 0
        length = 0
        while stop < valueLength:
            start = stop
            stop = min(start + maxChunkSize * 8, valueLength)
            length += encodeFun.computeLength(
                alignedValue[start:stop], asn1Spec, **options)

        return length

    def iterEncodeValue(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is not None:
            # TODO: try to avoid ASN.1 schema instantiation
            value = asn1Spec.clone(value)

        valueLength = len(value)
        if valueLength % 8:
            alignedValue = value << (8 - valueLength % 8)
        else:
            alignedValue = value

        maxChunkSize = options.get('maxChunkSize', 0)
        if not maxChunkSize or len(alignedValue) <= maxChunkSize * 8:
            substrate = alignedValue.asOctets()
            yield bytes((len(substrate) * 8 - valueLength,)) + substrate
            return

        if LOG:
            LOG('encoding into up to %s-octet chunks' % maxChunkSize)

        baseTag = value.tagSet.baseTag

        # strip off explicit tags
        if baseTag:
            tagSet = tag.TagSet(baseTag, baseTag)

        else:
            tagSet = tag.TagSet()

        alignedValue = alignedValue.clone(tagSet=tagSet)

        stop = 0
        while stop < valueLength:
            start = stop
            stop = min(start + maxChunkSize * 8, valueLength)
            for chunk in encodeFun.iterEncode(
                    alignedValue[start:stop], asn1Spec, **options):
                yield chunk


class OctetStringEncoder(AbstractItemEncoder):

    @staticmethod
    def _substrate(value, asn1Spec):
        if asn1Spec is None:
            substrate = value.asOctets()

        elif not isinstance(value, bytes):
            substrate = asn1Spec.clone(value).asOctets()

        else:
            substrate = value

        return substrate

    def encodeValue(self, value, asn1Spec, encodeFun, **options):

        substrate = self._substrate(value, asn1Spec)

        maxChunkSize = options.get('maxChunkSize', 0)

        if not maxChunkSize or len(substrate) <= maxChunkSize:
            return substrate, False, True

        if LOG:
            LOG('encoding into up to %s-octet chunks' % maxChunkSize)

        # strip off explicit tags for inner chunks

        if asn1Spec is None:
            baseTag = value.tagSet.baseTag

            # strip off explicit tags
            if baseTag:
                tagSet = tag.TagSet(baseTag, baseTag)

            else:
                tagSet = tag.TagSet()

            asn1Spec = value.clone(tagSet=tagSet)

        elif not isinstance(value, bytes):
            baseTag = asn1Spec.tagSet.baseTag

            # strip off explicit tags
            if baseTag:
                tagSet = tag.TagSet(baseTag, baseTag)

            else:
                tagSet = tag.TagSet()

            asn1Spec = asn1Spec.clone(tagSet=tagSet)

        pos = 0
        substrate = b''

        while True:
            chunk = value[pos:pos + maxChunkSize]
            if not chunk:
                break

            substrate += encodeFun(chunk, asn1Spec, **options)
            pos += maxChunkSize

        return substrate, True, True

    def isConstructedEncoding(self, value, asn1Spec, **options):
        maxChunkSize = options.get('maxChunkSize', 0)
        if not maxChunkSize:
            return False

        return len(self._substrate(value, asn1Spec)) > maxChunkSize

    def computeValueLength(self, value, asn1Spec, encodeFun, **options):

        substrate = self._substrate(value, asn1Spec)

        maxChunkSize = options.get('maxChunkSize', 0)

        if not maxChunkSize or len(substrate) <= maxChunkSize:
            return len(substrate)

        # strip off explicit tags for inner chunks

        if asn1Spec is None:
            baseTag = value.tagSet.baseTag

            # strip off explicit tags
            if baseTag:
                tagSet = tag.TagSet(baseTag, baseTag)

            else:
                tagSet = tag.TagSet()

            asn1Spec = value.clone(tagSet=tagSet)

        elif not isinstance(value, bytes):
            baseTag = asn1Spec.tagSet.baseTag

            # strip off explicit tags
            if baseTag:
                tagSet = tag.TagSet(baseTag, baseTag)

            else:
                tagSet = tag.TagSet()

            asn1Spec = asn1Spec.clone(tagSet=tagSet)

        pos = 0
        length = 0

        while True:
            chunk = value[pos:pos + maxChunkSize]
            if not chunk:
                break

            length += encodeFun.computeLength(chunk, asn1Spec, **options)
            pos += maxChunkSize

        return length

    def computeOctetsLength(self, octetsLength, asn1Spec, encodeFun, **options):
        """Compute the encoded length of an octet string payload of
        `octetsLength` octets encoded with `asn1Spec`, without
        materializing the payload.
        """
        maxChunkSize = options.get('maxChunkSize', 0)

        if not maxChunkSize or octetsLength <= maxChunkSize:
            contentLength = octetsLength
            isConstructed = False

        else:
            baseTag = asn1Spec.tagSet.baseTag

            # strip off explicit tags for inner chunks
            if baseTag:
                tagSet = tag.TagSet(baseTag, baseTag)

            else:
                tagSet = tag.TagSet()

            contentLength = 0
            pos = 0

            while pos < octetsLength:
                chunkSize = min(maxChunkSize, octetsLength - pos)

                layers = self._frameHeaders(chunkSize, False, tagSet, True)

                contentLength += chunkSize + sum(
                    len(header) + len(trailer) for header, trailer in layers)

                pos += maxChunkSize

            isConstructed = True

        layers = self._frameHeaders(
            contentLength, isConstructed, asn1Spec.tagSet,
            options.get('defMode', True))

        return contentLength + sum(
            len(header) + len(trailer) for header, trailer in layers)

    def iterEncodeValue(self, value, asn1Spec, encodeFun, **options):

        substrate = self._substrate(value, asn1Spec)

        maxChunkSize = options.get('maxChunkSize', 0)

        if not maxChunkSize or len(substrate) <= maxChunkSize:
            yield substrate
            return

        if LOG:
            LOG('encoding into up to %s-octet chunks' % maxChunkSize)

        # strip off explicit tags for inner chunks

        if asn1Spec is None:
            baseTag = value.tagSet.baseTag

            # strip off explicit tags
            if baseTag:
                tagSet = tag.TagSet(baseTag, baseTag)

            else:
                tagSet = tag.TagSet()

            asn1Spec = value.clone(tagSet=tagSet)

        elif not isinstance(value, bytes):
            baseTag = asn1Spec.tagSet.baseTag

            # strip off explicit tags
            if baseTag:
                tagSet = tag.TagSet(baseTag, baseTag)

            else:
                tagSet = tag.TagSet()

            asn1Spec = asn1Spec.clone(tagSet=tagSet)

        pos = 0

        while True:
            chunk = value[pos:pos + maxChunkSize]
            if not chunk:
                break

            for substrateChunk in encodeFun.iterEncode(
                    chunk, asn1Spec, **options):
                yield substrateChunk

            pos += maxChunkSize


class NullEncoder(AbstractItemEncoder):
    supportIndefLenMode = False

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        return b'', False, True


class ObjectIdentifierEncoder(AbstractItemEncoder):
    supportIndefLenMode = False

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is not None:
            value = asn1Spec.clone(value)

        oid = value.asTuple()

        # Build the first pair
        try:
            first = oid[0]
            second = oid[1]

        except IndexError:
            raise error.PyAsn1Error('Short OID %s' % (value,))

        if 0 <= second <= 39:
            if first == 1:
                oid = (second + 40,) + oid[2:]
            elif first == 0:
                oid = (second,) + oid[2:]
            elif first == 2:
                oid = (second + 80,) + oid[2:]
            else:
                raise error.PyAsn1Error('Impossible first/second arcs at %s' % (value,))

        elif first == 2:
            oid = (second + 80,) + oid[2:]

        else:
            raise error.PyAsn1Error('Impossible first/second arcs at %s' % (value,))

        octets = []

        # Cycle through subIds
        for subOid in oid:
            if 0 <= subOid <= 127:
                # Optimize for the common case
                octets.append(subOid)

            elif subOid > 127:
                # Pack large Sub-Object IDs
                res = [subOid & 0x7f]
                subOid >>= 7

                while subOid:
                    res.append(0x80 | (subOid & 0x7f))
                    subOid >>= 7

                # Add packed Sub-Object ID to resulted Object ID
                octets.extend(reversed(res))

            else:
                raise error.PyAsn1Error('Negative OID arc %s at %s' % (subOid, value))

        return tuple(octets), False, False


class RelativeOIDEncoder(AbstractItemEncoder):
    supportIndefLenMode = False

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is not None:
            value = asn1Spec.clone(value)

        octets = []

        # Cycle through subIds
        for subOid in value.asTuple():
            if 0 <= subOid <= 127:
                # Optimize for the common case
                octets.append(subOid)

            elif subOid > 127:
                # Pack large Sub-Object IDs
                res = [subOid & 0x7f]
                subOid >>= 7

                while subOid:
                    res.append(0x80 | (subOid & 0x7f))
                    subOid >>= 7

                # Add packed Sub-Object ID to resulted RELATIVE-OID
                octets.extend(reversed(res))

            else:
                raise error.PyAsn1Error('Negative RELATIVE-OID arc %s at %s' % (subOid, value))

        return tuple(octets), False, False


class RealEncoder(AbstractItemEncoder):
    supportIndefLenMode = False
    binEncBase = 2  # set to None to choose encoding base automatically

    @staticmethod
    def _dropFloatingPoint(m, encbase, e):
        ms, es = 1, 1
        if m < 0:
            ms = -1  # mantissa sign

        if e < 0:
            es = -1  # exponent sign

        m *= ms

        if encbase == 8:
            m *= 2 ** (abs(e) % 3 * es)
            e = abs(e) // 3 * es

        elif encbase == 16:
            m *= 2 ** (abs(e) % 4 * es)
            e = abs(e) // 4 * es

        while True:
            if int(m) != m:
                m *= encbase
                e -= 1
                continue
            break

        return ms, int(m), encbase, e

    def _chooseEncBase(self, value):
        m, b, e = value
        encBase = [2, 8, 16]
        if value.binEncBase in encBase:
            return self._dropFloatingPoint(m, value.binEncBase, e)

        elif self.binEncBase in encBase:
            return self._dropFloatingPoint(m, self.binEncBase, e)

        # auto choosing base 2/8/16
        mantissa = [m, m, m]
        exponent = [e, e, e]
        sign = 1
        encbase = 2
        e = float('inf')

        for i in range(3):
            (sign,
             mantissa[i],
             encBase[i],
             exponent[i]) = self._dropFloatingPoint(mantissa[i], encBase[i], exponent[i])

            if abs(exponent[i]) < abs(e) or (abs(exponent[i]) == abs(e) and mantissa[i] < m):
                e = exponent[i]
                m = int(mantissa[i])
                encbase = encBase[i]

        if LOG:
            LOG('automatically chosen REAL encoding base %s, sign %s, mantissa %s, '
                'exponent %s' % (encbase, sign, m, e))

        return sign, m, encbase, e

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is not None:
            value = asn1Spec.clone(value)

        if value.isPlusInf:
            return (0x40,), False, False

        if value.isMinusInf:
            return (0x41,), False, False

        m, b, e = value

        if not m:
            return b'', False, True

        if b == 10:
            if LOG:
                LOG('encoding REAL into character form')

            return b'\x03%dE%s%d' % (m, e == 0 and b'+' or b'', e), False, True

        elif b == 2:
            fo = 0x80  # binary encoding
            ms, m, encbase, e = self._chooseEncBase(value)

            if ms < 0:  # mantissa sign
                fo |= 0x40  # sign bit

            # exponent & mantissa normalization
            if encbase == 2:
                while m & 0x1 == 0:
                    m >>= 1
                    e += 1

            elif encbase == 8:
                while m & 0x7 == 0:
                    m >>= 3
                    e += 1
                fo |= 0x10

            else:  # encbase = 16
                while m & 0xf == 0:
                    m >>= 4
                    e += 1
                fo |= 0x20

            sf = 0  # scale factor

            while m & 0x1 == 0:
                m >>= 1
                sf += 1

            if sf > 3:
                raise error.PyAsn1Error('Scale factor overflow')  # bug if raised

            fo |= sf << 2
            eo = b''
            if e == 0 or e == -1:
                eo = bytes((e & 0xff,))

            else:
                while e not in (0, -1):
                    eo = bytes((e & 0xff,)) + eo
                    e >>= 8

                if e == 0 and eo and eo[0] & 0x80:
                    eo = bytes((0,)) + eo

                if e == -1 and eo and not (eo[0] & 0x80):
                    eo = bytes((0xff,)) + eo

            n = len(eo)
            if n > 0xff:
                raise error.PyAsn1Error('Real exponent overflow')

            if n == 1:
                pass

            elif n == 2:
                fo |= 1

            elif n == 3:
                fo |= 2

            else:
                fo |= 3
                eo = bytes((n & 0xff,)) + eo

            po = b''

            while m:
                po = bytes((m & 0xff,)) + po
                m >>= 8

            substrate = bytes((fo,)) + eo + po

            return substrate, False, True

        else:
            raise error.PyAsn1Error('Prohibited Real base %s' % b)


class SequenceEncoder(AbstractItemEncoder):
    omitEmptyOptionals = False

    # TODO: handling three flavors of input is too much -- split over codecs

    def _iterComponents(self, value, asn1Spec, options):
        """Yield (component, componentSpec, wrapType) per component to encode.

        The `options` dict is mutated in place (e.g. `ifNotEmpty`) exactly
        the way `encodeValue` used to do it, so callers observing the dict
        between iterations see the same state the old loop produced.
        """
        omitEmptyOptionals = options.get(
            'omitEmptyOptionals', self.omitEmptyOptionals)

        if LOG:
            LOG('%sencoding empty OPTIONAL components' % (
                    omitEmptyOptionals and 'not ' or ''))

        if asn1Spec is None:
            # instance of ASN.1 schema
            inconsistency = value.isInconsistent
            if inconsistency:
                raise error.PyAsn1Error(
                    f"ASN.1 object {value.__class__.__name__} is inconsistent")

            namedTypes = value.componentType

            for idx in range(value._componentTypeLen or len(value._dynamicNames)):
                component = value.getComponentByPosition(idx, instantiate=False)

                if namedTypes:
                    namedType = namedTypes[idx]

                    if component is univ.noValue and (
                            namedType.isOptional or namedType.isDefaulted):
                        continue
                    elif component is univ.noValue:
                        component = namedType.asn1Object

                    if namedType.isOptional and not component.isValue:
                        if LOG:
                            LOG('not encoding OPTIONAL component %r' % (namedType,))
                        continue

                    if namedType.isDefaulted and component == namedType.asn1Object:
                        if LOG:
                            LOG('not encoding DEFAULT component %r' % (namedType,))
                        continue

                    if omitEmptyOptionals:
                        options.update(ifNotEmpty=namedType.isOptional)

                    wrapType = None

                    # wrap open type blob if needed
                    if namedType.openType:
                        wrapType = namedType.asn1Object

                else:
                    wrapType = None

                yield component, asn1Spec, wrapType

        else:
            # bare Python value + ASN.1 schema
            for idx, namedType in enumerate(asn1Spec.componentType.namedTypes):

                try:
                    component = value[namedType.name]

                except KeyError:
                    raise error.PyAsn1Error('Component name "%s" not found in %r' % (
                        namedType.name, value))

                if namedType.isOptional and namedType.name not in value:
                    if LOG:
                        LOG('not encoding OPTIONAL component %r' % (namedType,))
                    continue

                if namedType.isDefaulted and component == namedType.asn1Object:
                    if LOG:
                        LOG('not encoding DEFAULT component %r' % (namedType,))
                    continue

                if omitEmptyOptionals:
                    options.update(ifNotEmpty=namedType.isOptional)

                componentSpec = namedType.asn1Object

                wrapType = None

                # wrap open type blob if needed
                if namedType.openType:
                    wrapType = componentSpec

                yield component, componentSpec, wrapType

    def encodeValue(self, value, asn1Spec, encodeFun, **options):

        substrate = b''

        for component, componentSpec, wrapType in self._iterComponents(
                value, asn1Spec, options):

            if wrapType is None:
                substrate += encodeFun(component, componentSpec, **options)

            elif wrapType.typeId in (
                    univ.SetOf.typeId, univ.SequenceOf.typeId):

                substrate += encodeFun(
                        component, componentSpec,
                        **dict(options, wrapType=wrapType.componentType))

            else:
                chunk = encodeFun(component, componentSpec, **options)

                if wrapType.isSameTypeWith(component):
                    substrate += chunk

                else:
                    substrate += encodeFun(chunk, wrapType, **options)

                    if LOG:
                        LOG('wrapped with wrap type %r' % (wrapType,))

        return substrate, True, True

    def isConstructedEncoding(self, value, asn1Spec, **options):
        return True

    def computeValueLength(self, value, asn1Spec, encodeFun, **options):

        length = 0

        for component, componentSpec, wrapType in self._iterComponents(
                value, asn1Spec, options):

            if wrapType is None:
                length += encodeFun.computeLength(
                    component, componentSpec, **options)

            elif wrapType.typeId in (
                    univ.SetOf.typeId, univ.SequenceOf.typeId):

                length += encodeFun.computeLength(
                        component, componentSpec,
                        **dict(options, wrapType=wrapType.componentType))

            else:
                chunkLength = encodeFun.computeLength(
                    component, componentSpec, **options)

                if wrapType.isSameTypeWith(component):
                    length += chunkLength

                else:
                    length += encodeFun.computeOctetsLength(
                        chunkLength, wrapType, **options)

        return length

    def iterEncodeValue(self, value, asn1Spec, encodeFun, **options):

        for component, componentSpec, wrapType in self._iterComponents(
                value, asn1Spec, options):

            if wrapType is None:
                for chunk in encodeFun.iterEncode(
                        component, componentSpec, **options):
                    yield chunk

            elif wrapType.typeId in (
                    univ.SetOf.typeId, univ.SequenceOf.typeId):

                for chunk in encodeFun.iterEncode(
                        component, componentSpec,
                        **dict(options, wrapType=wrapType.componentType)):
                    yield chunk

            elif wrapType.isSameTypeWith(component):
                for chunk in encodeFun.iterEncode(
                        component, componentSpec, **options):
                    yield chunk

            else:
                chunk = encodeFun(component, componentSpec, **options)

                for wrappedChunk in encodeFun.iterEncode(
                        chunk, wrapType, **options):
                    yield wrappedChunk


class SequenceOfEncoder(AbstractItemEncoder):
    def _iterComponents(self, value, asn1Spec, options):
        """Yield (component, componentSpec, wrapType) per component to encode.

        The `wrapType` option is destructively read from `options` exactly
        the way `_encodeComponents` used to do it.
        """
        if asn1Spec is None:
            inconsistency = value.isInconsistent
            if inconsistency:
                raise error.PyAsn1Error(
                    f"ASN.1 object {value.__class__.__name__} is inconsistent")

        else:
            asn1Spec = asn1Spec.componentType

        wrapType = options.pop('wrapType', None)

        for idx, component in enumerate(value):
            yield component, asn1Spec, wrapType

    def _encodeComponents(self, value, asn1Spec, encodeFun, **options):

        chunks = []

        for component, componentSpec, wrapType in self._iterComponents(
                value, asn1Spec, options):

            chunk = encodeFun(component, componentSpec, **options)

            if (wrapType is not None and
                    not wrapType.isSameTypeWith(component)):
                # wrap encoded value with wrapper container (e.g. ANY)
                chunk = encodeFun(chunk, wrapType, **options)

                if LOG:
                    LOG('wrapped with wrap type %r' % (wrapType,))

            chunks.append(chunk)

        return chunks

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        chunks = self._encodeComponents(
            value, asn1Spec, encodeFun, **options)

        return b''.join(chunks), True, True

    def isConstructedEncoding(self, value, asn1Spec, **options):
        return True

    def computeValueLength(self, value, asn1Spec, encodeFun, **options):

        length = 0

        for component, componentSpec, wrapType in self._iterComponents(
                value, asn1Spec, options):

            chunkLength = encodeFun.computeLength(
                component, componentSpec, **options)

            if (wrapType is not None and
                    not wrapType.isSameTypeWith(component)):
                # wrap encoded value with wrapper container (e.g. ANY)
                chunkLength = encodeFun.computeOctetsLength(
                    chunkLength, wrapType, **options)

            length += chunkLength

        return length

    def iterEncodeValue(self, value, asn1Spec, encodeFun, **options):

        for component, componentSpec, wrapType in self._iterComponents(
                value, asn1Spec, options):

            if (wrapType is not None and
                    not wrapType.isSameTypeWith(component)):
                # wrap encoded value with wrapper container (e.g. ANY)
                chunk = encodeFun(component, componentSpec, **options)

                for wrappedChunk in encodeFun.iterEncode(
                        chunk, wrapType, **options):
                    yield wrappedChunk

            else:
                for chunk in encodeFun.iterEncode(
                        component, componentSpec, **options):
                    yield chunk


class ChoiceEncoder(AbstractItemEncoder):
    @staticmethod
    def _resolveComponent(value, asn1Spec):
        if asn1Spec is None:
            component = value.getComponent()
        else:
            names = [namedType.name for namedType in asn1Spec.componentType.namedTypes
                     if namedType.name in value]
            if len(names) != 1:
                raise error.PyAsn1Error('%s components for Choice at %r' % (len(names) and 'Multiple ' or 'None ', value))

            name = names[0]

            component = value[name]
            asn1Spec = asn1Spec[name]

        return component, asn1Spec

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        component, asn1Spec = self._resolveComponent(value, asn1Spec)

        return encodeFun(component, asn1Spec, **options), True, True

    def isConstructedEncoding(self, value, asn1Spec, **options):
        return True

    def computeValueLength(self, value, asn1Spec, encodeFun, **options):
        component, asn1Spec = self._resolveComponent(value, asn1Spec)

        return encodeFun.computeLength(component, asn1Spec, **options)

    def iterEncodeValue(self, value, asn1Spec, encodeFun, **options):
        component, asn1Spec = self._resolveComponent(value, asn1Spec)

        for chunk in encodeFun.iterEncode(component, asn1Spec, **options):
            yield chunk


class AnyEncoder(OctetStringEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is None:
            value = value.asOctets()
        elif not isinstance(value, bytes):
            value = asn1Spec.clone(value).asOctets()

        return value, not options.get('defMode', True), True

    def isConstructedEncoding(self, value, asn1Spec, **options):
        return not options.get('defMode', True)

    def computeValueLength(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is None:
            value = value.asOctets()
        elif not isinstance(value, bytes):
            value = asn1Spec.clone(value).asOctets()

        return len(value)

    def computeOctetsLength(self, octetsLength, asn1Spec, encodeFun, **options):
        defMode = options.get('defMode', True)

        layers = self._frameHeaders(
            octetsLength, not defMode, asn1Spec.tagSet, defMode)

        return octetsLength + sum(
            len(header) + len(trailer) for header, trailer in layers)

    def iterEncodeValue(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is None:
            value = value.asOctets()
        elif not isinstance(value, bytes):
            value = asn1Spec.clone(value).asOctets()

        yield value


TAG_MAP = {
    eoo.endOfOctets.tagSet: EndOfOctetsEncoder(),
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
    char.UTF8String.tagSet: OctetStringEncoder(),
    char.NumericString.tagSet: OctetStringEncoder(),
    char.PrintableString.tagSet: OctetStringEncoder(),
    char.TeletexString.tagSet: OctetStringEncoder(),
    char.VideotexString.tagSet: OctetStringEncoder(),
    char.IA5String.tagSet: OctetStringEncoder(),
    char.GraphicString.tagSet: OctetStringEncoder(),
    char.VisibleString.tagSet: OctetStringEncoder(),
    char.GeneralString.tagSet: OctetStringEncoder(),
    char.UniversalString.tagSet: OctetStringEncoder(),
    char.BMPString.tagSet: OctetStringEncoder(),
    # useful types
    useful.ObjectDescriptor.tagSet: OctetStringEncoder(),
    useful.GeneralizedTime.tagSet: OctetStringEncoder(),
    useful.UTCTime.tagSet: OctetStringEncoder()
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
    univ.Set.typeId: SequenceEncoder(),
    univ.SetOf.typeId: SequenceOfEncoder(),
    univ.Sequence.typeId: SequenceEncoder(),
    univ.SequenceOf.typeId: SequenceOfEncoder(),
    univ.Choice.typeId: ChoiceEncoder(),
    univ.Any.typeId: AnyEncoder(),
    # character string types
    char.UTF8String.typeId: OctetStringEncoder(),
    char.NumericString.typeId: OctetStringEncoder(),
    char.PrintableString.typeId: OctetStringEncoder(),
    char.TeletexString.typeId: OctetStringEncoder(),
    char.VideotexString.typeId: OctetStringEncoder(),
    char.IA5String.typeId: OctetStringEncoder(),
    char.GraphicString.typeId: OctetStringEncoder(),
    char.VisibleString.typeId: OctetStringEncoder(),
    char.GeneralString.typeId: OctetStringEncoder(),
    char.UniversalString.typeId: OctetStringEncoder(),
    char.BMPString.typeId: OctetStringEncoder(),
    # useful types
    useful.ObjectDescriptor.typeId: OctetStringEncoder(),
    useful.GeneralizedTime.typeId: OctetStringEncoder(),
    useful.UTCTime.typeId: OctetStringEncoder()
}


class SingleItemEncoder(object):
    fixedDefLengthMode = None
    fixedChunkSize = None

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP

    def __init__(self, tagMap=_MISSING, typeMap=_MISSING, **ignored):
        self._tagMap = tagMap if tagMap is not _MISSING else self.TAG_MAP
        self._typeMap = typeMap if typeMap is not _MISSING else self.TYPE_MAP

    def _lookupEncoder(self, value, asn1Spec, options):
        try:
            if asn1Spec is None:
                typeId = value.typeId
            else:
                typeId = asn1Spec.typeId

        except AttributeError:
            raise error.PyAsn1Error('Value %r is not ASN.1 type instance '
                                    'and "asn1Spec" not given' % (value,))

        if LOG:
            LOG('encoder called in %sdef mode, chunk size %s for type %s, '
                'value:\n%s' % (not options.get('defMode', True) and 'in' or '',
                                options.get('maxChunkSize', 0),
                                asn1Spec is None and value.prettyPrintType() or
                                asn1Spec.prettyPrintType(), value))

        if self.fixedDefLengthMode is not None:
            options.update(defMode=self.fixedDefLengthMode)

        if self.fixedChunkSize is not None:
            options.update(maxChunkSize=self.fixedChunkSize)

        try:
            concreteEncoder = self._typeMap[typeId]

            if LOG:
                LOG('using value codec %s chosen by type ID '
                    '%s' % (concreteEncoder.__class__.__name__, typeId))

        except KeyError:
            if asn1Spec is None:
                tagSet = value.tagSet
            else:
                tagSet = asn1Spec.tagSet

            # use base type for codec lookup to recover untagged types
            baseTagSet = tag.TagSet(tagSet.baseTag, tagSet.baseTag)

            try:
                concreteEncoder = self._tagMap[baseTagSet]

            except KeyError:
                raise error.PyAsn1Error('No encoder for %r (%s)' % (value, tagSet))

            if LOG:
                LOG('using value codec %s chosen by tagSet '
                    '%s' % (concreteEncoder.__class__.__name__, tagSet))

        return concreteEncoder

    def __call__(self, value, asn1Spec=None, **options):
        concreteEncoder = self._lookupEncoder(value, asn1Spec, options)

        substrate = concreteEncoder.encode(value, asn1Spec, self, **options)

        if LOG:
            LOG('codec %s built %s octets of substrate: %s\nencoder '
                'completed' % (concreteEncoder, len(substrate),
                               debug.hexdump(substrate)))

        return substrate

    def computeLength(self, value, asn1Spec=None, **options):
        """Compute the number of octets the value encodes into."""
        concreteEncoder = self._lookupEncoder(value, asn1Spec, options)

        return concreteEncoder.computeLength(value, asn1Spec, self, **options)

    def computeOctetsLength(self, octetsLength, asn1Spec, **options):
        """Compute the encoded length of an octet string payload of
        `octetsLength` octets encoded with `asn1Spec`.
        """
        concreteEncoder = self._lookupEncoder(None, asn1Spec, options)

        return concreteEncoder.computeOctetsLength(
            octetsLength, asn1Spec, self, **options)

    def iterEncode(self, value, asn1Spec=None, **options):
        """Encode the value, returning a generator of substrate chunks."""
        concreteEncoder = self._lookupEncoder(value, asn1Spec, options)

        return concreteEncoder.iterEncode(value, asn1Spec, self, **options)


class Encoder(object):
    SINGLE_ITEM_ENCODER = SingleItemEncoder

    def __init__(self, tagMap=_MISSING, typeMap=_MISSING, **options):
        self._singleItemEncoder = self.SINGLE_ITEM_ENCODER(
            tagMap=tagMap, typeMap=typeMap, **options
        )

    def __call__(self, pyObject, asn1Spec=None, **options):
        return self._singleItemEncoder(
            pyObject, asn1Spec=asn1Spec, **options)

    def iterEncode(self, pyObject, asn1Spec=None, **options):
        return self._singleItemEncoder.iterEncode(
            pyObject, asn1Spec=asn1Spec, **options)


#: Turns ASN.1 object into BER octet stream.
#:
#: Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#: walks all its components recursively and produces a BER octet stream.
#:
#: Parameters
#: ----------
#: value: either a Python or pyasn1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     A Python or pyasn1 object to encode. If Python object is given, `asnSpec`
#:     parameter is required to guide the encoding process.
#:
#: Keyword Args
#: ------------
#: asn1Spec:
#:     Optional ASN.1 schema or value object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:
#: defMode: :py:class:`bool`
#:     If :obj:`False`, produces indefinite length encoding
#:
#: maxChunkSize: :py:class:`int`
#:     Maximum chunk size in chunked encoding mode (0 denotes unlimited chunk size)
#:
#: Returns
#: -------
#: : :py:class:`bytes`
#:     Given ASN.1 object encoded into BER octetstream
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error
#:     On encoding errors
#:
#: Examples
#: --------
#: Encode Python value into BER with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> encode([1, 2, 3], asn1Spec=seq)
#:    b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'
#:
#: Encode ASN.1 value object into BER
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> seq.extend([1, 2, 3])
#:    >>> encode(seq)
#:    b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'
#:
encode = Encoder()


def iterencode(value, asn1Spec=None, **options):
    """Turns ASN.1 object into BER octet stream, chunk by chunk.

    Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item`
    derivative), walks all its components recursively and produces a BER
    octet stream lazily, yielding substrate chunks as soon as they are
    available. Concatenating all the chunks yields exactly what
    :py:data:`~pyasn1.codec.ber.encoder.encode` returns.

    With definite length encoding (the default), content lengths are
    precomputed without materializing the encoded values. With indefinite
    length encoding (``defMode=False``), chunks are produced as the values
    are being encoded. In either case, stopping the iteration early avoids
    traversing the rest of the value.

    Parameters
    ----------
    value: either a Python or pyasn1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
        A Python or pyasn1 object to encode. If Python object is given, `asnSpec`
        parameter is required to guide the encoding process.

    Keyword Args
    ------------
    asn1Spec:
        Optional ASN.1 schema or value object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative

    defMode: :py:class:`bool`
        If :obj:`False`, produces indefinite length encoding

    maxChunkSize: :py:class:`int`
        Maximum chunk size in chunked encoding mode (0 denotes unlimited chunk size)

    Yields
    ------
    : :py:class:`bytes`
        Chunks of the BER octet stream

    Raises
    ------
    ~pyasn1.error.PyAsn1Error
        On encoding errors

    Examples
    --------
    Encode ASN.1 value object into BER, consuming the stream chunk by chunk:

    .. code-block:: pycon

       >>> seq = SequenceOf(componentType=Integer())
       >>> seq.extend([1, 2, 3])
       >>> for chunk in iterencode(seq):
       ...     send(chunk)
    """
    return encode.iterEncode(value, asn1Spec=asn1Spec, **options)


def __getattr__(attr: str):
    if newAttr := {"tagMap": "TAG_MAP", "typeMap": "TYPE_MAP"}.get(attr):
        warnings.warn(f"{attr} is deprecated. Please use {newAttr} instead.", DeprecationWarning, stacklevel=2)
        return globals()[newAttr]
    raise AttributeError(attr)
