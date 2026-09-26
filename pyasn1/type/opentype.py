#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#

from pyasn1 import error

__all__ = ['OpenType', 'OpenTypeContext']


class OpenTypeContext(object):
    """Resolution context handed to an OpenType resolver.

    Carries the state of the parent container at the moment the open
    type is resolved, along with the path of the open-typed field
    within the enclosing structure.

    A fresh context object is created for every open type resolution,
    so nested open types, elements of SET OF/SEQUENCE OF open
    type fields and concurrently running decoders never share
    resolution state.

    Parameters
    ----------
    parent: :py:class:`~pyasn1.type.base.Asn1Item`
        The parent container ASN.1 object holding the open-typed field

    path: :py:class:`tuple`
        Field path (component names and container positions) leading
        to the open-typed field, outermost first
    """

    def __init__(self, parent, path):
        self.__parent = parent
        self.__path = tuple(path)

    @property
    def parent(self):
        """Parent container ASN.1 object being decoded"""
        return self.__parent

    @property
    def path(self):
        """Field path to the open-typed field, outermost first"""
        return self.__path

    def sibling(self, name):
        """Return a decoded sibling component by name.

        Open types are resolved only after the enclosing container
        payload has been decoded, and a resolver must not peek at
        sibling fields that carry no value. This accessor fails
        loudly whenever the requested dependency can not be satisfied.

        Parameters
        ----------
        name: :py:class:`str`
            Sibling field name

        Returns
        -------
        :py:class:`~pyasn1.type.base.Asn1Item`
            The decoded sibling value

        Raises
        ------
        :py:class:`~pyasn1.error.PyAsn1Error`
            If the sibling field does not exist or carries no value
        """
        try:
            value = self.__parent.getComponentByName(name)

        except error.PyAsn1Error:
            raise error.PyAsn1Error(
                'OpenType field %s has no sibling field %r' % (self, name))

        if not value.isValue:
            raise error.PyAsn1Error(
                'OpenType resolver dependency %r at %s is not decoded' % (
                    name, self))

        return value

    def __repr__(self):
        return '%s(%s)' % (
            self.__class__.__name__, '.'.join(map(str, self.__path)))


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
        Optional callable taking the governing field value and an
        :py:class:`OpenTypeContext`, returning the ASN.1 type to decode
        the open type field with. Unlike the static *typeMap*, a resolver
        can consult other already-decoded fields of the parent container
        (e.g. a protocol version) through the context. Returning
        :py:class:`None` falls back to the static *typeMap* lookup.

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

    For version-dependent resolution:

    .. code-block:: python

        def resolve(governingValue, context):
            if context.sibling('version') == 2:
                return NewPayload()
            return OldPayload()

        openType = OpenType('id', resolver=resolve)
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
        if resolver is not None and not callable(resolver):
            raise error.PyAsn1Error(
                'OpenType resolver %r is not callable' % (resolver,))
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
