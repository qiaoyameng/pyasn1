#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1 import error
from pyasn1.type import char
from pyasn1.type import compatcheck
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ


class SmallInt(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 50)


class BigInt(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 100)


class EvenInt(univ.Integer):
    subtypeSpec = constraint.SingleValueConstraint(0, 2, 4)


class EvenIntPlus(univ.Integer):
    subtypeSpec = constraint.SingleValueConstraint(0, 2, 4, 6)


class ShortString(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(1, 5)


class LongString(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(1, 10)


class AbcString(char.IA5String):
    subtypeSpec = constraint.PermittedAlphabetConstraint('a', 'b', 'c')


class AbString(char.IA5String):
    subtypeSpec = constraint.PermittedAlphabetConstraint('a', 'b')


class CustomConstraint(constraint.AbstractConstraint):
    def _testValue(self, value, idx):
        pass


class VersionedThingV1(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.Integer()),
        namedtype.NamedType('name', univ.OctetString())
    )


class VersionedThingV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.Integer()),
        namedtype.NamedType('name', univ.OctetString()),
        namedtype.OptionalNamedType('email', char.IA5String())
    )


class VersionedThingV3(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.Integer()),
        namedtype.NamedType('name', univ.OctetString()),
        namedtype.NamedType('email', char.IA5String())
    )


class ReorderedThing(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', univ.OctetString()),
        namedtype.NamedType('id', univ.Integer())
    )


class NodeV1(univ.Sequence):
    pass


NodeV1.componentType = namedtype.NamedTypes(
    namedtype.NamedType('value', BigInt()),
    namedtype.OptionalNamedType('next', NodeV1())
)


class NodeV2(univ.Sequence):
    pass


NodeV2.componentType = namedtype.NamedTypes(
    namedtype.NamedType('value', SmallInt()),
    namedtype.OptionalNamedType('next', NodeV2())
)


class ReportApiTestCase(BaseTestCase):
    def testCompatibleVerdict(self):
        report = compatcheck.checkCompatibility(
            univ.Integer(), univ.Integer())
        assert report.verdict == compatcheck.COMPATIBLE
        assert not report.findings
        assert report

    def testIncompatibleVerdict(self):
        report = compatcheck.checkCompatibility(BigInt(), SmallInt())
        assert report.verdict == compatcheck.INCOMPATIBLE
        assert not report
        assert len(report.findings) == 1

    def testUnknownDominatesCompatible(self):
        report = compatcheck.CompatibilityReport([
            compatcheck.Finding('x', compatcheck.UNKNOWN, 'why')])
        assert report.verdict == compatcheck.UNKNOWN
        assert not report

    def testFindingAttributes(self):
        finding = compatcheck.Finding('a.b', compatcheck.UNKNOWN, 'why')
        assert finding.path == 'a.b'
        assert finding.verdict == compatcheck.UNKNOWN
        assert finding.reason == 'why'
        assert finding == compatcheck.Finding(
            'a.b', compatcheck.UNKNOWN, 'why')
        assert finding != compatcheck.Finding(
            'a.c', compatcheck.UNKNOWN, 'why')

    def testNonSchemaArgumentRejected(self):
        try:
            compatcheck.checkCompatibility('not a schema', univ.Integer())
        except error.PyAsn1Error:
            pass
        else:
            assert 0, 'non-schema oldSchema tolerated'

        try:
            compatcheck.checkCompatibility(univ.Integer(), None)
        except error.PyAsn1Error:
            pass
        else:
            assert 0, 'non-schema newSchema tolerated'


class TagChangeTestCase(BaseTestCase):
    def testTagChangeIsIncompatible(self):
        old = univ.Integer()
        new = univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 3))
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.INCOMPATIBLE
        assert 'tag changed' in report.findings[0].reason

    def testTypeKindChangeIsIncompatible(self):
        report = compatcheck.checkCompatibility(
            univ.Integer(), univ.OctetString())
        assert report.verdict == compatcheck.INCOMPATIBLE

    def testSequenceVsSequenceOfIsIncompatible(self):
        # Both share the universal constructed tag 16
        old = univ.SequenceOf(componentType=univ.Integer())
        new = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer())))
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.INCOMPATIBLE


class ValueRangeTestCase(BaseTestCase):
    def testTightenedRangeIsIncompatible(self):
        report = compatcheck.checkCompatibility(BigInt(), SmallInt())
        assert report.verdict == compatcheck.INCOMPATIBLE
        finding = report.findings[0]
        assert finding.path == 'BigInt'
        assert '0..100' in finding.reason
        assert '0..50' in finding.reason

    def testLoosenedRangeIsCompatible(self):
        report = compatcheck.checkCompatibility(SmallInt(), BigInt())
        assert report.verdict == compatcheck.COMPATIBLE

    def testDirectionalityIsNotSymmetric(self):
        forward = compatcheck.checkCompatibility(BigInt(), SmallInt())
        backward = compatcheck.checkCompatibility(SmallInt(), BigInt())
        assert forward.verdict != backward.verdict

    def testConstraintAddedWhereUnconstrained(self):
        report = compatcheck.checkCompatibility(
            univ.Integer(), SmallInt())
        assert report.verdict == compatcheck.INCOMPATIBLE

    def testConstraintRemovedIsCompatible(self):
        report = compatcheck.checkCompatibility(
            SmallInt(), univ.Integer())
        assert report.verdict == compatcheck.COMPATIBLE


class SizeConstraintTestCase(BaseTestCase):
    def testTightenedSizeIsIncompatible(self):
        report = compatcheck.checkCompatibility(
            LongString(), ShortString())
        assert report.verdict == compatcheck.INCOMPATIBLE

    def testLoosenedSizeIsCompatible(self):
        report = compatcheck.checkCompatibility(
            ShortString(), LongString())
        assert report.verdict == compatcheck.COMPATIBLE


class SingleValueTestCase(BaseTestCase):
    def testNarrowedValueSetIsIncompatible(self):
        report = compatcheck.checkCompatibility(
            EvenIntPlus(), EvenInt())
        assert report.verdict == compatcheck.INCOMPATIBLE

    def testWidenedValueSetIsCompatible(self):
        report = compatcheck.checkCompatibility(
            EvenInt(), EvenIntPlus())
        assert report.verdict == compatcheck.COMPATIBLE


class PermittedAlphabetTestCase(BaseTestCase):
    def testNarrowedAlphabetIsIncompatible(self):
        report = compatcheck.checkCompatibility(
            AbcString(), AbString())
        assert report.verdict == compatcheck.INCOMPATIBLE

    def testWidenedAlphabetIsCompatible(self):
        report = compatcheck.checkCompatibility(
            AbString(), AbcString())
        assert report.verdict == compatcheck.COMPATIBLE


class UnknownConstraintTestCase(BaseTestCase):
    def testCustomConstraintOnNewSchemaIsUnknown(self):
        new = univ.Integer().clone(
            subtypeSpec=constraint.ConstraintsIntersection(
                CustomConstraint()))
        report = compatcheck.checkCompatibility(univ.Integer(), new)
        assert report.verdict == compatcheck.UNKNOWN

    def testCustomConstraintNotJudgedCompatible(self):
        # Known constraints admit all old values, but the custom
        # constraint might reject anything: never COMPATIBLE
        new = univ.Integer().clone(
            subtypeSpec=constraint.ConstraintsIntersection(
                constraint.ValueRangeConstraint(0, 100),
                CustomConstraint()))
        report = compatcheck.checkCompatibility(SmallInt(), new)
        assert report.verdict == compatcheck.UNKNOWN

    def testProvenIncompatibleDominatesUnknown(self):
        # Old value 50 violates the known range no matter what the
        # custom constraint does
        new = univ.Integer().clone(
            subtypeSpec=constraint.ConstraintsIntersection(
                constraint.ValueRangeConstraint(0, 10),
                CustomConstraint()))
        report = compatcheck.checkCompatibility(BigInt(), new)
        assert report.verdict == compatcheck.INCOMPATIBLE

    def testUnionConstraintIsUnknown(self):
        new = univ.Integer().clone(
            subtypeSpec=constraint.ConstraintsIntersection(
                constraint.ConstraintsUnion(
                    constraint.SingleValueConstraint(1),
                    constraint.SingleValueConstraint(2))))
        report = compatcheck.checkCompatibility(univ.Integer(), new)
        assert report.verdict == compatcheck.UNKNOWN


class SequenceMembersTestCase(BaseTestCase):
    def testAddedOptionalFieldIsCompatible(self):
        report = compatcheck.checkCompatibility(
            VersionedThingV1(), VersionedThingV2())
        assert report.verdict == compatcheck.COMPATIBLE

    def testRemovedOptionalFieldIsIncompatible(self):
        # The reverse direction: V2 encodings may carry 'email'
        report = compatcheck.checkCompatibility(
            VersionedThingV2(), VersionedThingV1())
        assert report.verdict == compatcheck.INCOMPATIBLE
        finding = report.findings[0]
        assert finding.path == 'VersionedThingV2.email'
        assert 'removed' in finding.reason

    def testAddedRequiredFieldIsIncompatible(self):
        report = compatcheck.checkCompatibility(
            VersionedThingV1(), VersionedThingV3())
        assert report.verdict == compatcheck.INCOMPATIBLE
        finding = report.findings[0]
        assert finding.path == 'VersionedThingV1.email'
        assert 'required field' in finding.reason

    def testFieldOrderChangeIsIncompatible(self):
        report = compatcheck.checkCompatibility(
            VersionedThingV1(), ReorderedThing())
        assert report.verdict == compatcheck.INCOMPATIBLE
        reasons = [f.reason for f in report.findings]
        assert any('order changed' in r for r in reasons)

    def testSetFieldOrderChangeIsCompatible(self):
        old = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('name', univ.OctetString())))
        new = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('name', univ.OctetString()),
            namedtype.NamedType('id', univ.Integer())))
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.COMPATIBLE

    def testOptionalBecomingRequiredIsIncompatible(self):
        old = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.OptionalNamedType('id', univ.Integer())))
        new = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer())))
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.INCOMPATIBLE
        assert 'became required' in report.findings[0].reason

    def testRequiredBecomingOptionalIsCompatible(self):
        old = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer())))
        new = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.OptionalNamedType('id', univ.Integer())))
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.COMPATIBLE

    def testNestedFieldConstraintPath(self):
        old = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('age', BigInt())))
        new = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('age', SmallInt())))
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.INCOMPATIBLE
        assert report.findings[0].path == 'Sequence.age'


class ChoiceTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.old = univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer()),
            namedtype.NamedType('b', univ.OctetString())))
        self.narrowed = univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer())))
        self.extended = univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer()),
            namedtype.NamedType('b', univ.OctetString()),
            namedtype.NamedType('c', univ.Boolean())))

    def testRemovedAlternativeIsIncompatible(self):
        report = compatcheck.checkCompatibility(self.old, self.narrowed)
        assert report.verdict == compatcheck.INCOMPATIBLE
        finding = report.findings[0]
        assert finding.path == 'Choice.b'
        assert 'alternative' in finding.reason

    def testAddedAlternativeIsCompatible(self):
        report = compatcheck.checkCompatibility(self.old, self.extended)
        assert report.verdict == compatcheck.COMPATIBLE

    def testAlternativeTypeChangeIsIncompatible(self):
        new = univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer()),
            namedtype.NamedType('b', univ.Boolean())))
        report = compatcheck.checkCompatibility(self.old, new)
        assert report.verdict == compatcheck.INCOMPATIBLE

    def testChoiceVsNonChoiceIsIncompatible(self):
        report = compatcheck.checkCompatibility(
            self.old, univ.Integer())
        assert report.verdict == compatcheck.INCOMPATIBLE


class SequenceOfTestCase(BaseTestCase):
    def testElementTypeChangeIsIncompatible(self):
        old = univ.SequenceOf(componentType=univ.Integer())
        new = univ.SequenceOf(componentType=univ.OctetString())
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.INCOMPATIBLE
        assert report.findings[0].path == 'SequenceOf[*]'

    def testElementConstraintTightenedIsIncompatible(self):
        old = univ.SequenceOf(componentType=BigInt())
        new = univ.SequenceOf(componentType=SmallInt())
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.INCOMPATIBLE

    def testSizeConstraintTightenedIsIncompatible(self):
        old = univ.SequenceOf(componentType=univ.Integer()).clone(
            subtypeSpec=constraint.ConstraintsIntersection(
                constraint.ValueSizeConstraint(1, 10)))
        new = univ.SequenceOf(componentType=univ.Integer()).clone(
            subtypeSpec=constraint.ConstraintsIntersection(
                constraint.ValueSizeConstraint(1, 5)))
        report = compatcheck.checkCompatibility(old, new)
        assert report.verdict == compatcheck.INCOMPATIBLE


class RecursiveSchemaTestCase(BaseTestCase):
    def testIdenticalRecursiveSchemaTerminates(self):
        report = compatcheck.checkCompatibility(NodeV1(), NodeV1())
        assert report.verdict == compatcheck.COMPATIBLE

    def testRecursiveConstraintTighteningIsFound(self):
        report = compatcheck.checkCompatibility(NodeV1(), NodeV2())
        assert report.verdict == compatcheck.INCOMPATIBLE
        finding = report.findings[0]
        assert finding.path == 'NodeV1.value'

    def testReverseDirectionIsCompatible(self):
        report = compatcheck.checkCompatibility(NodeV2(), NodeV1())
        assert report.verdict == compatcheck.COMPATIBLE


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
