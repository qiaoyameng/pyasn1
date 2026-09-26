#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import univ
from pyasn1.type import tag
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.error import PyAsn1Error


class UntaggedAnyTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        class Sequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.Any())
            )

        self.s = Sequence()

    def testTypeCheckOnAssignment(self):

        self.s.clear()

        self.s['blob'] = univ.Any(b'xxx')

        # this should succeed because Any is untagged and unconstrained
        self.s['blob'] = univ.Integer(123)


class TaggedAnyTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        self.taggedAny = univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassPrivate, tag.tagFormatSimple, 20))

        class Sequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', self.taggedAny)
            )

        self.s = Sequence()

    def testTypeCheckOnAssignment(self):

        self.s.clear()

        self.s['blob'] = self.taggedAny.clone('xxx')

        try:
            self.s.setComponentByName('blob', univ.Integer(123))

        except PyAsn1Error:
            pass

        else:
            assert False, 'non-open type assignment tolerated'


class TaggedAnyOpenTypeTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        self.taggedAny = univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassPrivate, tag.tagFormatSimple, 20))

        class Sequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', self.taggedAny, openType=opentype.OpenType(name='id'))
            )

        self.s = Sequence()

    def testTypeCheckOnAssignment(self):

        self.s.clear()

        self.s['blob'] = univ.Any(b'xxx')
        self.s['blob'] = univ.Integer(123)


class OpenTypeResolverTestCase(BaseTestCase):

    def testResolverStored(self):
        def resolve(governingValue, context):
            return univ.Integer()

        ot = opentype.OpenType('id', resolver=resolve)

        assert ot.resolver is resolve
        assert ot.name == 'id'

    def testNoResolver(self):
        integer = univ.Integer()
        ot = opentype.OpenType('id', {1: integer})

        assert ot.resolver is None
        assert ot[1] is integer

    def testNonCallableResolver(self):
        try:
            opentype.OpenType('id', resolver='not-callable')

        except PyAsn1Error:
            pass

        else:
            assert False, 'non-callable resolver tolerated'


class OpenTypeContextTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        class Sequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('version', univ.Integer()),
                namedtype.OptionalNamedType('comment', univ.OctetString())
            )

        self.parent = Sequence()
        self.parent['version'] = 2

        self.context = opentype.OpenTypeContext(self.parent, ('blob',))

    def testAttributes(self):
        assert self.context.parent is self.parent
        assert self.context.path == ('blob',)

    def testSibling(self):
        assert self.context.sibling('version') == 2

    def testSiblingNotDecoded(self):
        try:
            self.context.sibling('comment')

        except PyAsn1Error:
            pass

        else:
            assert False, 'undecoded sibling read tolerated'

    def testSiblingUnknown(self):
        try:
            self.context.sibling('nosuch')

        except PyAsn1Error:
            pass

        else:
            assert False, 'unknown sibling read tolerated'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
