#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""JSON-safe, lossless representation of ASN.1 values.

This package implements a self-describing, JSON-serialisable format on
top of the same codec skeleton as :mod:`pyasn1.codec.native`, but with
a tree composed exclusively of JSON-safe Python objects: ``dict``,
``list``, ``str``, ``bool`` and ``None``. No ``bytes``, no tuples, no
bare ``int`` or ``float`` (whose JSON rendering is not canonical).

Values that JSON scalars cannot express losslessly are wrapped into
single-key *tagged* objects. All tag names start with ``$``, a
character that can never appear in an ASN.1 identifier, so a SEQUENCE
or SET encoded as a plain JSON object (its keys being component names)
can never be mistaken for a tagged special value, and an arbitrary
business dictionary can only collide with the format if it uses
``$``-prefixed keys itself - which the decoder rejects wherever the
schema does not expect them.

Decoding always requires an ``asn1Spec`` schema; the JSON document
alone never selects or imports a Python class.
"""

#: Tagged-object key wrapping INTEGER and ENUMERATED values. The
#: payload is a decimal (or, for integers too large for the
#: interpreter's int-to-str limit, ``0x``-prefixed hexadecimal) string.
TAG_INTEGER = '$int'

#: Tagged-object key wrapping REAL values. The payload is the Python
#: ``repr()`` of the float, covering also 'inf', '-inf' and 'nan'.
TAG_REAL = '$real'

#: Tagged-object key wrapping OCTET STRING and ANY values. The payload
#: is standard base64 without whitespace.
TAG_BYTES = '$bytes'

#: Tagged-object key wrapping BIT STRING values. The payload is a
#: string of '0'/'1' characters whose length is the effective number
#: of bits.
TAG_BITS = '$bits'

#: Tagged-object key wrapping OBJECT IDENTIFIER and RELATIVE-OID
#: values. The payload is the dotted-decimal string.
TAG_OID = '$oid'

#: Tagged-object key wrapping CHOICE values. The payload is a
#: single-key object mapping the chosen alternative's name to its
#: encoded value.
TAG_CHOICE = '$choice'

#: All tag names, for validation purposes.
ALL_TAGS = frozenset([
    TAG_INTEGER, TAG_REAL, TAG_BYTES, TAG_BITS, TAG_OID, TAG_CHOICE
])
