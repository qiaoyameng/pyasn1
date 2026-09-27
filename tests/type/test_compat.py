#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.error import PyAsn1Error
from pyasn1.type import compat
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ


class CustomConstraint(constraint.AbstractConstraint):
    def _testValue(self, value, idx):
        pass


class Person(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', univ.OctetString()),
        namedtype.NamedType('age', univ.Integer())
    )


class PersonWithNickname(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', univ.OctetString()),
        namedtype.NamedType('age', univ.Integer()),
        namedtype.OptionalNamedType('nickname', univ.OctetString())
    )


class PersonReordered(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('age', univ.Integer()),
        namedtype.NamedType('name', univ.OctetString())
    )


class Node(univ.Sequence):
    pass


Node.componentType = namedtype.NamedTypes(
    namedtype.NamedType('value', univ.Integer()),
    namedtype.OptionalNamedType('next', Node())
)


class TightNode(univ.Sequence):
    pass


TightNode.componentType = namedtype.NamedTypes(
    namedtype.NamedType('value', univ.Integer().subtype(
        subtypeSpec=constraint.ValueRangeConstraint(0, 100))),
    namedtype.OptionalNamedType('next', TightNode())
)


class ReportTestCase(BaseTestCase):

    def testStatusCompatible(self):
        report = compat.checkCompatibility(univ.Integer(), univ.Integer())
        assert report.status == compat.COMPATIBLE
        assert report.issues == ()
        assert report

    def testStatusIncompatibleBeatsUnknown(self):
        issues = [
            compat.CompatibilityIssue('A', compat.UNKNOWN, 'u'),
            compat.CompatibilityIssue('B', compat.INCOMPATIBLE, 'i'),
        ]
        report = compat.CompatibilityReport(issues)
        assert report.status == compat.INCOMPATIBLE
        assert not report

    def testStatusUnknown(self):
        report = compat.CompatibilityReport(
            [compat.CompatibilityIssue('A', compat.UNKNOWN, 'u')])
        assert report.status == compat.UNKNOWN
        assert not report

    def testIssueAttributes(self):
        issue = compat.CompatibilityIssue('A.b', compat.INCOMPATIBLE, 'why')
        assert issue.path == 'A.b'
        assert issue.status == compat.INCOMPATIBLE
        assert issue.reason == 'why'
        assert 'A.b' in repr(issue)
        assert 'incompatible' in repr(compat.CompatibilityReport([issue]))

    def testNonSchemaArgumentRejected(self):
        try:
            compat.checkCompatibility(univ.Integer(), 42)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'non-schema argument tolerated'


class TagAndKindTestCase(BaseTestCase):

    def testIdenticalSchemas(self):
        report = compat.checkCompatibility(Person(), Person())
        assert report.status == compat.COMPATIBLE

    def testTagChange(self):
        old = univ.Integer()
        new = univ.Integer().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 1))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.INCOMPATIBLE
        assert 'tag' in report.issues[0].reason

    def testTypeChange(self):
        report = compat.checkCompatibility(univ.Integer(), univ.OctetString())
        assert report.status == compat.INCOMPATIBLE

    def testKindChangeSameTag(self):
        # SEQUENCE and SEQUENCE OF share the universal tag 16
        old = univ.Sequence()
        new = univ.SequenceOf(componentType=univ.Integer())
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.INCOMPATIBLE
        assert 'kind' in report.issues[0].reason


class SequenceMemberTestCase(BaseTestCase):

    def testOptionalMemberAdded(self):
        report = compat.checkCompatibility(Person(), PersonWithNickname())
        assert report.status == compat.COMPATIBLE

    def testOptionalMemberAddedReverse(self):
        report = compat.checkCompatibility(PersonWithNickname(), Person())
        assert report.status == compat.INCOMPATIBLE
        assert report.issues[0].path == 'PersonWithNickname.nickname'

    def testRequiredMemberAdded(self):
        class PersonWithRequired(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('name', univ.OctetString()),
                namedtype.NamedType('age', univ.Integer()),
                namedtype.NamedType('id', univ.Integer())
            )

        report = compat.checkCompatibility(Person(), PersonWithRequired())
        assert report.status == compat.INCOMPATIBLE
        assert report.issues[0].path == 'Person.id'

    def testDefaultedMemberAdded(self):
        class PersonWithDefault(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('name', univ.OctetString()),
                namedtype.NamedType('age', univ.Integer()),
                namedtype.DefaultedNamedType('id', univ.Integer(0))
            )

        report = compat.checkCompatibility(Person(), PersonWithDefault())
        assert report.status == compat.COMPATIBLE

    def testOptionalBecomesRequired(self):
        class PersonRequired(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('name', univ.OctetString()),
                namedtype.NamedType('age', univ.Integer()),
                namedtype.NamedType('nickname', univ.OctetString())
            )

        report = compat.checkCompatibility(
            PersonWithNickname(), PersonRequired())
        assert report.status == compat.INCOMPATIBLE
        assert 'nickname' in report.issues[0].path

    def testRequiredBecomesOptional(self):
        class PersonOptional(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('name', univ.OctetString()),
                namedtype.NamedType('age', univ.Integer())
            )

        report = compat.checkCompatibility(Person(), PersonOptional())
        assert report.status == compat.COMPATIBLE

    def testMemberOrderChanged(self):
        report = compat.checkCompatibility(Person(), PersonReordered())
        assert report.status == compat.INCOMPATIBLE
        assert 'order' in report.issues[0].reason

    def testSetOrderChangeIgnored(self):
        class BagA(univ.Set):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('name', univ.OctetString()),
                namedtype.NamedType('age', univ.Integer())
            )

        class BagB(univ.Set):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('age', univ.Integer()),
                namedtype.NamedType('name', univ.OctetString())
            )

        report = compat.checkCompatibility(BagA(), BagB())
        assert report.status == compat.COMPATIBLE

    def testNestedMemberPath(self):
        class Wrapper(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('person', PersonWithNickname())
            )

        class WrapperOld(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('person', Person())
            )

        report = compat.checkCompatibility(Wrapper(), WrapperOld())
        assert report.status == compat.INCOMPATIBLE
        assert report.issues[0].path == 'Wrapper.person.nickname'


class SequenceOfTestCase(BaseTestCase):

    def testComponentTightened(self):
        old = univ.SequenceOf(componentType=univ.Integer())
        new = univ.SequenceOf(componentType=univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 10)))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.INCOMPATIBLE
        assert report.issues[0].path == 'SequenceOf[*]'

    def testComponentWidened(self):
        old = univ.SequenceOf(componentType=univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 10)))
        new = univ.SequenceOf(componentType=univ.Integer())
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.COMPATIBLE

    def testUntypedComponent(self):
        report = compat.checkCompatibility(
            univ.SequenceOf(), univ.SequenceOf(componentType=univ.Integer()))
        assert report.status == compat.UNKNOWN


class ChoiceTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        class ChoiceA(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', univ.Integer()),
                namedtype.NamedType('text', univ.OctetString())
            )

        class ChoiceB(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', univ.Integer()),
                namedtype.NamedType('text', univ.OctetString()),
                namedtype.NamedType('flag', univ.Boolean())
            )

        self.choiceA = ChoiceA()
        self.choiceB = ChoiceB()

    def testAlternativeAdded(self):
        report = compat.checkCompatibility(self.choiceA, self.choiceB)
        assert report.status == compat.COMPATIBLE

    def testAlternativeRemoved(self):
        report = compat.checkCompatibility(self.choiceB, self.choiceA)
        assert report.status == compat.INCOMPATIBLE
        assert report.issues[0].path == 'ChoiceB.flag'

    def testAlternativeConstraintTightened(self):
        class ChoiceTight(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', univ.Integer().subtype(
                    subtypeSpec=constraint.ValueRangeConstraint(0, 5))),
                namedtype.NamedType('text', univ.OctetString())
            )

        report = compat.checkCompatibility(self.choiceA, ChoiceTight())
        assert report.status == compat.INCOMPATIBLE
        assert report.issues[0].path == 'ChoiceA.number'

    def testChoiceVersusNonChoice(self):
        report = compat.checkCompatibility(self.choiceA, univ.Integer())
        assert report.status == compat.INCOMPATIBLE


class ConstraintTestCase(BaseTestCase):

    def testRangeTightened(self):
        old = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 255))
        new = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 100))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.INCOMPATIBLE

    def testRangeWidened(self):
        old = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 100))
        new = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 255))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.COMPATIBLE

    def testRangeAddedToUnconstrained(self):
        new = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 100))
        report = compat.checkCompatibility(univ.Integer(), new)
        assert report.status == compat.INCOMPATIBLE

    def testConstraintDropped(self):
        old = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 100))
        report = compat.checkCompatibility(old, univ.Integer())
        assert report.status == compat.COMPATIBLE

    def testSizeTightened(self):
        old = univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 10))
        new = univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 5))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.INCOMPATIBLE
        assert compat.checkCompatibility(new, old).status == compat.COMPATIBLE

    def testAlphabetTightened(self):
        old = univ.OctetString().subtype(
            subtypeSpec=constraint.PermittedAlphabetConstraint('a', 'b', 'c'))
        new = univ.OctetString().subtype(
            subtypeSpec=constraint.PermittedAlphabetConstraint('a', 'b'))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.INCOMPATIBLE
        assert compat.checkCompatibility(new, old).status == compat.COMPATIBLE

    def testSingleValueWidened(self):
        old = univ.Integer().subtype(
            subtypeSpec=constraint.SingleValueConstraint(1, 2))
        new = univ.Integer().subtype(
            subtypeSpec=constraint.SingleValueConstraint(1, 2, 3))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.COMPATIBLE
        assert compat.checkCompatibility(
            new, old).status == compat.INCOMPATIBLE

    def testSingleValueWithinRange(self):
        old = univ.Integer().subtype(
            subtypeSpec=constraint.SingleValueConstraint(1, 2))
        new = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 10))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.COMPATIBLE

    def testSmallRangeWithinSingleValues(self):
        old = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(1, 3))
        new = univ.Integer().subtype(
            subtypeSpec=constraint.SingleValueConstraint(1, 2, 3, 4))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.COMPATIBLE

    def testCustomConstraintIsUnknown(self):
        new = univ.Integer().subtype(subtypeSpec=CustomConstraint(1, 2))
        report = compat.checkCompatibility(univ.Integer(), new)
        assert report.status == compat.UNKNOWN
        assert report.issues[0].status == compat.UNKNOWN

    def testCustomConstraintOnOldSideOnly(self):
        old = univ.Integer().subtype(subtypeSpec=CustomConstraint(1, 2))
        report = compat.checkCompatibility(old, univ.Integer())
        assert report.status == compat.COMPATIBLE

    def testCustomConstraintShadowsKnownVerdict(self):
        old = univ.Integer().subtype(subtypeSpec=CustomConstraint(1, 2))
        new = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 10))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.UNKNOWN

    def testBuiltinSubclassIsUnknown(self):
        class MyRange(constraint.ValueRangeConstraint):
            pass

        new = univ.Integer().subtype(subtypeSpec=MyRange(0, 10))
        report = compat.checkCompatibility(univ.Integer(), new)
        assert report.status == compat.UNKNOWN

    def testExclusionConstraintIsUnknown(self):
        new = univ.Integer().subtype(
            subtypeSpec=constraint.ConstraintsExclusion(
                constraint.SingleValueConstraint(13)))
        report = compat.checkCompatibility(univ.Integer(), new)
        assert report.status == compat.UNKNOWN

    def testUnionConstraint(self):
        old = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 10))
        new = univ.Integer().subtype(subtypeSpec=constraint.ConstraintsUnion(
            constraint.ValueRangeConstraint(0, 5),
            constraint.ValueRangeConstraint(6, 20)))
        report = compat.checkCompatibility(old, new)
        assert report.status == compat.COMPATIBLE


class RecursiveSchemaTestCase(BaseTestCase):

    def testRecursiveIdentical(self):
        report = compat.checkCompatibility(Node(), Node())
        assert report.status == compat.COMPATIBLE

    def testRecursiveTightened(self):
        report = compat.checkCompatibility(Node(), TightNode())
        assert report.status == compat.INCOMPATIBLE
        assert report.issues[0].path == 'Node.value'

    def testRecursiveWidened(self):
        report = compat.checkCompatibility(TightNode(), Node())
        assert report.status == compat.COMPATIBLE

    def testRecursiveOptionalMemberAdded(self):
        class RichNode(univ.Sequence):
            pass

        RichNode.componentType = namedtype.NamedTypes(
            namedtype.NamedType('value', univ.Integer()),
            namedtype.OptionalNamedType('label', univ.OctetString()),
            namedtype.OptionalNamedType('next', RichNode())
        )

        report = compat.checkCompatibility(Node(), RichNode())
        assert report.status == compat.COMPATIBLE
        report = compat.checkCompatibility(RichNode(), Node())
        assert report.status == compat.INCOMPATIBLE


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
