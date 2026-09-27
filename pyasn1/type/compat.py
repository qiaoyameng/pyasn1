#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""ASN.1 schema compatibility checker.

This module answers a single question: given an *old* schema and a
*new* schema, is every value the old schema can encode also accepted
by the new schema?  It is meant for protocol evolution reviews, where
a schema is about to be upgraded and the operator wants to know
whether peers still running the old schema can keep talking to peers
that already run the new one.

The check is purely static: it reads the two schema objects (tags,
component types and subtype constraints) and never instantiates ASN.1
values, never builds sample encodings and never calls user-supplied
constraint code.

The verdict is three-valued:

* ``COMPATIBLE`` -- every value of the old schema is provably
  accepted by the new schema;
* ``INCOMPATIBLE`` -- the old schema admits at least one value the
  new schema provably rejects;
* ``UNKNOWN`` -- the checker cannot decide, typically because a
  custom (user-defined) constraint object is involved.  An
  unanalysable constraint is never assumed compatible.

Every finding is reported as a :class:`CompatibilityIssue` carrying
the dotted path of the offending schema node and a human-readable
reason.

The relation is directional: ``checkCompatibility(a, b)`` returning
``COMPATIBLE`` says nothing about ``checkCompatibility(b, a)``.
Widening a value range or adding an optional field is compatible in
one direction and incompatible in the other.
"""
from pyasn1 import error
from pyasn1.type import base
from pyasn1.type import constraint
from pyasn1.type import univ

__all__ = ['COMPATIBLE', 'INCOMPATIBLE', 'UNKNOWN',
           'CompatibilityIssue', 'CompatibilityReport',
           'checkCompatibility']

#: Verdict: every value of the old schema is accepted by the new schema
COMPATIBLE = 'compatible'

#: Verdict: the old schema admits values the new schema rejects
INCOMPATIBLE = 'incompatible'

#: Verdict: the checker cannot decide (e.g. custom constraints involved)
UNKNOWN = 'unknown'

# Largest integer range the checker enumerates when testing a
# ValueRangeConstraint against a SingleValueConstraint
_MAX_RANGE_ENUMERATION = 1024

_KIND_SIMPLE = 'simple type'
_KIND_SEQUENCE = 'SEQUENCE/SET'
_KIND_SEQUENCE_OF = 'SEQUENCE OF/SET OF'
_KIND_CHOICE = 'CHOICE'


class CompatibilityIssue(object):
    """A single schema compatibility finding.

    Attributes
    ----------
    path: :class:`str`
        Dotted path of the schema node the finding applies to, rooted
        at the old schema's class name.  ``SEQUENCE OF`` components
        are addressed as ``[*]``.
    status: :class:`str`
        Either ``INCOMPATIBLE`` or ``UNKNOWN``.
    reason: :class:`str`
        Human-readable explanation of the finding.
    """

    def __init__(self, path, status, reason):
        self._path = path
        self._status = status
        self._reason = reason

    @property
    def path(self):
        return self._path

    @property
    def status(self):
        return self._status

    @property
    def reason(self):
        return self._reason

    def __repr__(self):
        return '%s(path=%r, status=%r, reason=%r)' % (
            self.__class__.__name__, self._path, self._status, self._reason)


class CompatibilityReport(object):
    """Aggregated outcome of :func:`checkCompatibility`.

    Attributes
    ----------
    issues: :class:`tuple` of :class:`CompatibilityIssue`
        All findings, in schema traversal order.  Empty when the
        verdict is ``COMPATIBLE``.
    status: :class:`str`
        ``INCOMPATIBLE`` if any issue is incompatible, else
        ``UNKNOWN`` if any issue is unknown, else ``COMPATIBLE``.
    """

    def __init__(self, issues=()):
        self._issues = tuple(issues)

    @property
    def issues(self):
        return self._issues

    @property
    def status(self):
        statuses = set(issue.status for issue in self._issues)
        if INCOMPATIBLE in statuses:
            return INCOMPATIBLE
        if UNKNOWN in statuses:
            return UNKNOWN
        return COMPATIBLE

    def __bool__(self):
        return self.status == COMPATIBLE

    def __repr__(self):
        return '%s(status=%r, issues=%r)' % (
            self.__class__.__name__, self.status, list(self._issues))


def checkCompatibility(oldSchema, newSchema):
    """Check that every value of *oldSchema* is accepted by *newSchema*.

    The two schemas are compared structurally: ASN.1 tags, SEQUENCE/SET
    member presence, order and optionality, CHOICE alternatives and
    subtype constraints (value ranges, size ranges, permitted
    alphabets and single values).  Recursive schemas are supported;
    the traversal terminates on already-visited schema pairs.

    Parameters
    ----------
    oldSchema: :py:class:`~pyasn1.type.base.Asn1Item`
        ASN.1 schema object currently in use.

    newSchema: :py:class:`~pyasn1.type.base.Asn1Item`
        ASN.1 schema object about to be deployed.

    Returns
    -------
    : :class:`CompatibilityReport`
        The aggregated verdict and all findings.

    Raises
    ------
    ~pyasn1.error.PyAsn1Error
        If either argument is not an ASN.1 schema object.
    """
    for schema in oldSchema, newSchema:
        if not isinstance(schema, base.Asn1Item):
            raise error.PyAsn1Error(
                'ASN.1 schema object expected, got %r' % (schema,))

    comparator = _SchemaComparator()
    comparator.compare(oldSchema, newSchema, oldSchema.__class__.__name__)

    return CompatibilityReport(comparator.issues)


def _kindOf(schema):
    if isinstance(schema, univ.Choice):
        return _KIND_CHOICE
    if isinstance(schema, univ.SequenceOfAndSetOfBase):
        return _KIND_SEQUENCE_OF
    if isinstance(schema, univ.SequenceAndSetBase):
        return _KIND_SEQUENCE
    return _KIND_SIMPLE


class _SchemaComparator(object):
    """Recursive pair-wise schema walker accumulating issues."""

    def __init__(self):
        self.issues = []
        self._visitedPairs = set()

    def compare(self, old, new, path):
        pair = id(old), id(new)
        if pair in self._visitedPairs:
            return
        self._visitedPairs.add(pair)

        oldKind = _kindOf(old)
        newKind = _kindOf(new)

        if oldKind != newKind:
            self._addIssue(
                path, INCOMPATIBLE,
                'ASN.1 type kind changed from %s to %s' % (oldKind, newKind))
            return

        if oldKind != _KIND_CHOICE and old.tagSet != new.tagSet:
            self._addIssue(
                path, INCOMPATIBLE,
                'ASN.1 tag changed from %s to %s' % (old.tagSet, new.tagSet))
            return

        self._compareConstraints(old, new, path)

        if oldKind == _KIND_SEQUENCE_OF:
            self._compareSequenceOf(old, new, path)
        elif oldKind == _KIND_SEQUENCE:
            self._compareNamedTypes(old, new, path)
        elif oldKind == _KIND_CHOICE:
            self._compareChoice(old, new, path)

    def _addIssue(self, path, status, reason):
        self.issues.append(CompatibilityIssue(path, status, reason))

    def _compareSequenceOf(self, old, new, path):
        oldComponent = old.componentType
        newComponent = new.componentType

        if oldComponent is None or newComponent is None:
            if oldComponent is not newComponent:
                self._addIssue(
                    path, UNKNOWN,
                    'component type is defined on one side only')
            return

        self.compare(oldComponent, newComponent, path + '[*]')

    def _compareNamedTypes(self, old, new, path):
        oldTypes = old.componentType
        newTypes = new.componentType

        pairedNewPositions = []

        for oldPos in range(len(oldTypes)):
            oldNamedType = oldTypes[oldPos]
            name = oldNamedType.name
            memberPath = '%s.%s' % (path, name)

            if name not in newTypes:
                self._addIssue(
                    memberPath, INCOMPATIBLE,
                    'member %r is absent from the new schema' % name)
                continue

            newNamedType = newTypes[name]
            pairedNewPositions.append(newTypes.getPositionByName(name))

            oldOptional = (oldNamedType.isOptional or
                           oldNamedType.isDefaulted)
            newOptional = (newNamedType.isOptional or
                           newNamedType.isDefaulted)

            if oldOptional and not newOptional:
                self._addIssue(
                    memberPath, INCOMPATIBLE,
                    'member %r is optional or defaulted in the old schema '
                    'but required in the new schema' % name)

            self.compare(
                oldNamedType.asn1Object, newNamedType.asn1Object, memberPath)

        for newPos in range(len(newTypes)):
            newNamedType = newTypes[newPos]

            if newNamedType.name in oldTypes:
                continue

            if not (newNamedType.isOptional or newNamedType.isDefaulted):
                self._addIssue(
                    '%s.%s' % (path, newNamedType.name), INCOMPATIBLE,
                    'required member %r of the new schema is absent from '
                    'the old schema' % newNamedType.name)

        if (isinstance(old, univ.Sequence) and
                pairedNewPositions != sorted(pairedNewPositions)):
            self._addIssue(
                path, INCOMPATIBLE,
                'member order changed between the schemas')

    def _compareChoice(self, old, new, path):
        oldTypes = old.componentType
        newTypes = new.componentType

        for oldPos in range(len(oldTypes)):
            oldNamedType = oldTypes[oldPos]
            name = oldNamedType.name

            if name not in newTypes:
                self._addIssue(
                    '%s.%s' % (path, name), INCOMPATIBLE,
                    'CHOICE alternative %r is absent from the new '
                    'schema' % name)
                continue

            self.compare(
                oldNamedType.asn1Object, newTypes[name].asn1Object,
                '%s.%s' % (path, name))

    def _compareConstraints(self, old, new, path):
        oldSpec = old.subtypeSpec
        newSpec = new.subtypeSpec

        if not newSpec or oldSpec == newSpec:
            return

        oldConjuncts = list(_flattenIntersection(oldSpec))

        for newConstraint in _flattenIntersection(newSpec):
            if not newConstraint:
                continue

            verdict = _isImplied(oldConjuncts, newConstraint)

            if verdict is True:
                continue

            if verdict is False:
                self._addIssue(
                    path, INCOMPATIBLE,
                    'new schema constraint %r narrows the value space '
                    'beyond what the old schema permits' % (newConstraint,))
            else:
                self._addIssue(
                    path, UNKNOWN,
                    'new schema constraint %r cannot be analysed '
                    'statically' % (newConstraint,))


def _flattenIntersection(spec):
    if type(spec) is constraint.ConstraintsIntersection:
        for subConstraint in spec:
            for leaf in _flattenIntersection(subConstraint):
                yield leaf
    else:
        yield spec


def _isImplied(oldConjuncts, newConstraint):
    """Three-valued test: does the old constraint set imply the new one?

    Returns True (provably implied), False (provably not implied) or
    None (cannot decide).
    """
    newType = type(newConstraint)

    if newType is constraint.ConstraintsIntersection:
        verdict = True
        for subConstraint in newConstraint:
            subVerdict = _isImplied(oldConjuncts, subConstraint)
            if subVerdict is False:
                return False
            if subVerdict is None:
                verdict = None
        return verdict

    if newType is constraint.ConstraintsUnion:
        operands = list(newConstraint)

        payloads = [_constraintKindAndPayload(operand) for operand in operands]

        if all(kind is not None for kind, _ in payloads):
            for oldConstraint in oldConjuncts:
                if _coveredByUnion(oldConstraint, payloads):
                    return True

        for subConstraint in operands:
            if _isImplied(oldConjuncts, subConstraint) is True:
                return True
        return None

    if _constraintKindAndPayload(newConstraint)[0] is None:
        return None

    oldFullyKnown = True

    for oldConstraint in oldConjuncts:
        verdict = _constraintImplies(oldConstraint, newConstraint)
        if verdict is True:
            return True
        if verdict is None:
            oldFullyKnown = False

    if oldFullyKnown:
        return False

    return None


def _coveredByUnion(oldConstraint, unionPayloads):
    """Test if an old constraint is covered by a union of known kinds."""
    oldKind, oldPayload = _constraintKindAndPayload(oldConstraint)

    if oldKind is None:
        return False

    kinds = set(kind for kind, _ in unionPayloads)

    if oldKind in ('range', 'size') and kinds == set([oldKind]):
        return _intervalsCover(
            [payload for _, payload in unionPayloads], *oldPayload)

    if oldKind == 'values':
        if kinds == set(['values']):
            unionValues = frozenset().union(
                *[payload for _, payload in unionPayloads])
            return oldPayload <= unionValues
        if kinds == set(['range']):
            intervals = [payload for _, payload in unionPayloads]
            try:
                return all(
                    any(lower <= value <= upper for lower, upper in intervals)
                    for value in oldPayload)
            except TypeError:
                return False

    if oldKind == 'range' and kinds == set(['values']):
        unionValues = frozenset().union(
            *[payload for _, payload in unionPayloads])
        oldLower, oldUpper = oldPayload
        try:
            if oldUpper - oldLower > _MAX_RANGE_ENUMERATION:
                return False
            return all(
                value in unionValues
                for value in range(oldLower, oldUpper + 1))
        except TypeError:
            return False

    return False


def _intervalsCover(intervals, lower, upper):
    """Test if sorted intervals contiguously cover [lower, upper]."""
    try:
        integerSteps = all(
            isinstance(bound, int)
            for interval in intervals for bound in interval)
        integerSteps = (integerSteps and isinstance(lower, int) and
                        isinstance(upper, int))

        needed = lower

        for lo, hi in sorted(intervals):
            if lo > needed:
                return False
            if integerSteps:
                needed = max(needed, hi + 1)
            else:
                needed = max(needed, hi)

        if integerSteps:
            return needed > upper

        return needed >= upper

    except TypeError:
        return False


def _constraintImplies(oldConstraint, newConstraint):
    """Three-valued test: does a single old constraint imply the new one?"""
    oldType = type(oldConstraint)

    if oldType is constraint.ConstraintsUnion:
        verdict = True
        for subConstraint in oldConstraint:
            subVerdict = _constraintImplies(subConstraint, newConstraint)
            if subVerdict is False:
                return False
            if subVerdict is None:
                verdict = None
        return verdict

    if oldType is constraint.ConstraintsIntersection:
        verdict = False
        for subConstraint in oldConstraint:
            subVerdict = _constraintImplies(subConstraint, newConstraint)
            if subVerdict is True:
                return True
            if subVerdict is None:
                verdict = None
        return verdict

    oldKind, oldPayload = _constraintKindAndPayload(oldConstraint)
    newKind, newPayload = _constraintKindAndPayload(newConstraint)

    if oldKind is None or newKind is None:
        return None

    return _knownPairImplies(oldKind, oldPayload, newKind, newPayload)


def _constraintKindAndPayload(singleConstraint):
    """Classify an exactly-typed built-in constraint.

    Subclasses of the built-in constraints are deliberately not
    recognised: they may carry user-defined test logic that must not
    be executed and cannot be assumed compatible.
    """
    constraintType = type(singleConstraint)

    if constraintType is constraint.ValueSizeConstraint:
        return 'size', (singleConstraint.start, singleConstraint.stop)

    if constraintType is constraint.ValueRangeConstraint:
        return 'range', (singleConstraint.start, singleConstraint.stop)

    if constraintType is constraint.PermittedAlphabetConstraint:
        return 'alphabet', frozenset(singleConstraint._values)

    if constraintType is constraint.SingleValueConstraint:
        return 'values', frozenset(singleConstraint._values)

    return None, None


def _knownPairImplies(oldKind, oldPayload, newKind, newPayload):
    if newKind == 'range':
        lower, upper = newPayload
        if oldKind == 'range':
            oldLower, oldUpper = oldPayload
            return oldLower >= lower and oldUpper <= upper
        if oldKind == 'values':
            try:
                return all(lower <= value <= upper for value in oldPayload)
            except TypeError:
                return None
        return False

    if newKind == 'size':
        if oldKind != 'size':
            return False
        lower, upper = newPayload
        oldLower, oldUpper = oldPayload
        return oldLower >= lower and oldUpper <= upper

    if newKind == 'alphabet':
        if oldKind != 'alphabet':
            return False
        return oldPayload <= newPayload

    if newKind == 'values':
        if oldKind == 'values':
            return oldPayload <= newPayload
        if oldKind == 'range':
            oldLower, oldUpper = oldPayload
            try:
                if oldUpper - oldLower > _MAX_RANGE_ENUMERATION:
                    return None
                return all(
                    value in newPayload
                    for value in range(oldLower, oldUpper + 1))
            except TypeError:
                return None
        return False

    return None
