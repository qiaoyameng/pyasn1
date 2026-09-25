#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#

__all__ = ['OpenType']


class OpenType(object):
    """Create ASN.1 type map indexed by a value

    The *OpenType* object models an untyped field of a constructed ASN.1
    type. In ASN.1 syntax it is usually represented by the
    `ANY DEFINED BY` for scalars or `SET OF ANY DEFINED BY`,
    `SEQUENCE OF ANY DEFINED BY` for container types clauses. Typically
    used together with :class:`~pyasn1.type.univ.Any` object.

    OpenType objects duck-type a read-only Python :class:`dict` objects,
    however the passed `typeMap` is not copied, but stored by reference.
    That means the user can manipulate `typeMap` at run time having this
    reflected on *OpenType* object behavior.

    The |OpenType| class models an untyped field of a constructed ASN.1
    type. In ASN.1 syntax it is usually represented by the
    `ANY DEFINED BY` for scalars or `SET OF ANY DEFINED BY`,
    `SEQUENCE OF ANY DEFINED BY` for container types clauses. Typically
    used with :class:`~pyasn1.type.univ.Any` type.

    Parameters
    ----------
    name: :py:class:`str`
        Field name

    typeMap: :py:class:`dict`
        A map of value->ASN.1 type. It's stored by reference and can be
        mutated later to register new mappings.

    resolver: callable
        Optional callable resolving the ASN.1 type of the untyped field
        at decode time. It is consulted (instead of `typeMap` and the
        decoder's `openTypes` option) whenever open types are decoded,
        e.g. under `decodeOpenTypes=True`.

        The callable is invoked as
        ``resolver(governingValue, container, fieldPath)`` where
        `governingValue` is the decoded value of the field named `name`,
        `container` is the fully decoded parent ASN.1 container object
        (sibling fields, e.g. a protocol version, can be read from it),
        and `fieldPath` is a tuple of field names (and
        `SEQUENCE OF`/`SET OF` element positions) locating the untyped
        field within the decoded structure.

        The callable must return an ASN.1 type object to decode the
        field payload with. If it raises, or returns an object that is
        not an ASN.1 type, decoding fails with
        :py:class:`~pyasn1.error.PyAsn1Error` reporting the field
        position; the raw payload is never retried as another type.

    Examples
    --------

    For untyped scalars:

    .. code-block:: python

        openType = OpenType(
            'id', {1: Integer(),
                   2: OctetString()}
        )
        Sequence(
            componentType=NamedTypes(
                NamedType('id', Integer()),
                NamedType('blob', Any(), openType=openType)
            )
        )

    For untyped `SET OF` or `SEQUENCE OF` vectors:

    .. code-block:: python

        openType = OpenType(
            'id', {1: Integer(),
                   2: OctetString()}
        )
        Sequence(
            componentType=NamedTypes(
                NamedType('id', Integer()),
                NamedType('blob', SetOf(componentType=Any()),
                          openType=openType)
            )
        )

    For protocol-version-dependent typing:

    .. code-block:: python

        def resolveByVersion(governingValue, container, fieldPath):
            if container['version'] == 1:
                return Integer()
            return OctetString()

        openType = OpenType('id', resolver=resolveByVersion)
        Sequence(
            componentType=NamedTypes(
                NamedType('version', Integer()),
                NamedType('id', ObjectIdentifier()),
                NamedType('blob', Any(), openType=openType)
            )
        )
    """

    def __init__(self, name, typeMap=None, resolver=None):
        self.__name = name
        if typeMap is None:
            self.__typeMap = {}
        else:
            self.__typeMap = typeMap
        self.__resolver = resolver

    @property
    def name(self):
        return self.__name

    @property
    def resolver(self):
        return self.__resolver

    # Python dict protocol

    def values(self):
        return self.__typeMap.values()

    def keys(self):
        return self.__typeMap.keys()

    def items(self):
        return self.__typeMap.items()

    def __contains__(self, key):
        return key in self.__typeMap

    def __getitem__(self, key):
        return self.__typeMap[key]

    def __iter__(self):
        return iter(self.__typeMap)
