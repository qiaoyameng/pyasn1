#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Directed schema-to-schema compatibility check.

This module answers a single directed question: given an *old* and a
*new* ASN.1 schema, can every value encodable under the old schema be
accepted (decoded and constraint-validated) by the new one?

The check is purely static. It reads schema objects -- tags, component
types, optionality and subtype constraints -- and never instantiates
values, never builds sample encodings and never calls user-supplied
constraint callables.

The relation is not symmetric: a new schema that only adds an OPTIONAL
field accepts everything the old schema encodes, while the reverse
direction does not. Always check the direction you care about.
"""
from pyasn1 import error
from pyasn1.type import base
from pyasn1.type import constraint
from pyasn1.type import univ

__all__ = ['COMPATIBLE', 'INCOMPATIBLE', 'UNKNOWN', 'Finding',
           'CompatibilityReport', 'checkCompatibility']

#: Every value of the old schema is provably accepted by the new one
COMPATIBLE = 'compatible'

#: A value of the old schema exists that the new schema rejects
INCOMPATIBLE = 'incompatible'

#: The check can not decide, e.g. custom constraint objects are involved
UNKNOWN = 'unknown'

_verdictRanks = {COMPATIBLE: 0, UNKNOWN: 1, INCOMPATIBLE: 2}


class Finding(object):
    """A single compatibility observation at a schema location.

    Attributes
    ----------
    path: :class:`str`
        Dotted path to the schema element the finding refers to, rooted
        at the old schema type name. ``[*]`` marks a SEQUENCE OF/SET OF
        element, other segments are component or alternative names.

    verdict: :class:`str`
        One of `COMPATIBLE`, `INCOMPATIBLE` or `UNKNOWN`.

    reason: :class:`str`
        Human-readable explanation of the observation.
    """

    def __init__(self, path, verdict, reason):
        self._path = path
        self._verdict = verdict
        self._reason = reason

    @property
    def path(self):
        return self._path

    @property
    def verdict(self):
        return self._verdict

    @property
    def reason(self):
        return self._reason

    def __repr__(self):
        return '<%s object, path %s, verdict %s, reason %s>' % (
            self.__class__.__name__, self._path, self._verdict,
            self._reason)

    def __eq__(self, other):
        return (self._path, self._verdict, self._reason) == (
            other.path, other.verdict, other.reason)

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self._path, self._verdict, self._reason))


class CompatibilityReport(object):
    """Aggregated outcome of :func:`checkCompatibility`.

    Attributes
    ----------
    findings: :class:`tuple`
        All :class:`Finding` objects collected during the check, in
        discovery order. Empty when the schemas are fully compatible.

    verdict: :class:`str`
        The worst verdict over all findings: `INCOMPATIBLE` if any
        finding is incompatible, else `UNKNOWN` if any finding is
        undecidable, else `COMPATIBLE`.
    """

    def __init__(self, findings=()):
        self._findings = tuple(findings)

    @property
    def findings(self):
        return self._findings

    @property
    def verdict(self):
        worst = COMPATIBLE
        for finding in self._findings:
            if _verdictRanks[finding.verdict] > _verdictRanks[worst]:
                worst = finding.verdict
        return worst

    def __bool__(self):
        return self.verdict == COMPATIBLE

    def __repr__(self):
        return '<%s object, verdict %s, %d finding(s)>' % (
            self.__class__.__name__, self.verdict, len(self._findings))


def checkCompatibility(oldSchema, newSchema):
    """Check that every value of *oldSchema* is accepted by *newSchema*.

    The two schemas are compared structurally: tags, SEQUENCE/SET
    members (order, presence, optionality), CHOICE alternatives,
    SEQUENCE OF/SET OF element types and value range, size, permitted
    alphabet and single-value constraints. Recursive schemas are
    supported: each pair of already-visited schema objects terminates
    the descent.

    The check never instantiates values and never calls constraint
    callables. Constraint objects it does not recognize (custom
    :py:class:`~pyasn1.type.constraint.AbstractConstraint` subclasses,
    unions, exclusions, ``WITH COMPONENTS``) make the affected node
    `UNKNOWN` rather than silently compatible.

    Parameters
    ----------
    oldSchema: |ASN.1| schema object
        The schema existing values were encoded with.

    newSchema: |ASN.1| schema object
        The schema those values are about to be decoded with.

    Returns
    -------
    : :class:`CompatibilityReport`
        The aggregated verdict and all findings.

    Raises
    ------
    ~pyasn1.error.PyAsn1Error
        If either argument is not an |ASN.1| schema object.
    """
    if not isinstance(oldSchema, base.Asn1Type):
        raise error.PyAsn1Error(
            'oldSchema must be an ASN.1 schema object, got %r' % (
                oldSchema,))

    if not isinstance(newSchema, base.Asn1Type):
        raise error.PyAsn1Error(
            'newSchema must be an ASN.1 schema object, got %r' % (
                newSchema,))

    findings = []

    _checkTypes(oldSchema, newSchema, oldSchema.__class__.__name__,
                findings, set())

    return CompatibilityReport(findings)


def _checkTypes(old, new, path, findings, visited):
    pair = id(old), id(new)

    if pair in visited:
        # Recursive schema: this pair is already being checked up the
        # stack, so coinductively assume it compatible.
        return

    visited.add(pair)

    if isinstance(new, univ.Any):
        # ANY accepts arbitrary payload
        return

    if isinstance(old, univ.Any):
        findings.append(Finding(
            path, UNKNOWN,
            'old schema is ANY and may hold arbitrary payload'))
        return

    oldIsChoice = isinstance(old, univ.Choice)
    newIsChoice = isinstance(new, univ.Choice)

    if oldIsChoice != newIsChoice:
        findings.append(Finding(
            path, INCOMPATIBLE,
            'type kind changed from %s to %s' % (
                old.__class__.__name__, new.__class__.__name__)))
        return

    if oldIsChoice:
        _checkChoice(old, new, path, findings, visited)
        _checkConstraints(old, new, path, findings)
        return

    if old.tagSet != new.tagSet:
        findings.append(Finding(
            path, INCOMPATIBLE,
            'tag changed from %s to %s' % (old.tagSet, new.tagSet)))
        return

    oldIsSequenceOf = isinstance(old, univ.SequenceOfAndSetOfBase)
    newIsSequenceOf = isinstance(new, univ.SequenceOfAndSetOfBase)
    oldIsRecord = isinstance(old, univ.SequenceAndSetBase)
    newIsRecord = isinstance(new, univ.SequenceAndSetBase)

    if oldIsSequenceOf != newIsSequenceOf or oldIsRecord != newIsRecord:
        findings.append(Finding(
            path, INCOMPATIBLE,
            'type kind changed from %s to %s' % (
                old.__class__.__name__, new.__class__.__name__)))
        return

    if oldIsSequenceOf:
        _checkSequenceOf(old, new, path, findings, visited)

    elif oldIsRecord:
        _checkRecord(old, new, path, findings, visited)

    _checkConstraints(old, new, path, findings)


def _checkSequenceOf(old, new, path, findings, visited):
    oldComponent = old.componentType
    newComponent = new.componentType

    if newComponent is None:
        # Untyped elements in the new schema accept anything
        return

    if oldComponent is None:
        findings.append(Finding(
            path + '[*]', UNKNOWN,
            'old schema leaves the element type unconstrained'))
        return

    _checkTypes(oldComponent, newComponent, path + '[*]',
                findings, visited)


def _checkRecord(old, new, path, findings, visited):
    # SET members are unordered on the wire, SEQUENCE members are not
    ordered = not isinstance(old, univ.Set)

    oldNamedTypes = old.componentType.namedTypes
    newNamedTypes = new.componentType.namedTypes

    newByName = {}
    for idx, namedType in enumerate(newNamedTypes):
        newByName[namedType.name] = idx, namedType

    matched = set()
    cursor = 0

    for oldNamedType in oldNamedTypes:
        fieldPath = '%s.%s' % (path, oldNamedType.name)

        if oldNamedType.openType is not None:
            findings.append(Finding(
                fieldPath, UNKNOWN, 'field has an open type'))

        entry = newByName.get(oldNamedType.name)

        if entry is None:
            findings.append(Finding(
                fieldPath, INCOMPATIBLE,
                'field was removed in new schema'))
            continue

        newIdx, newNamedType = entry

        if ordered and newIdx < cursor:
            findings.append(Finding(
                fieldPath, INCOMPATIBLE,
                'field order changed in new schema'))
            continue

        if ordered:
            for skippedIdx in range(cursor, newIdx):
                if skippedIdx in matched:
                    continue
                skipped = newNamedTypes[skippedIdx]
                if not skipped.isOptional and not skipped.isDefaulted:
                    findings.append(Finding(
                        '%s.%s' % (path, skipped.name), INCOMPATIBLE,
                        'required field was added in new schema'))
                matched.add(skippedIdx)
            cursor = newIdx + 1

        matched.add(newIdx)

        oldOmittable = (oldNamedType.isOptional or
                        oldNamedType.isDefaulted)
        newOmittable = (newNamedType.isOptional or
                        newNamedType.isDefaulted)

        if oldOmittable and not newOmittable:
            findings.append(Finding(
                fieldPath, INCOMPATIBLE,
                'field became required in new schema'))

        if newNamedType.openType is not None:
            findings.append(Finding(
                fieldPath, UNKNOWN, 'field has an open type'))

        _checkTypes(oldNamedType.asn1Object, newNamedType.asn1Object,
                    fieldPath, findings, visited)

    for newIdx, newNamedType in enumerate(newNamedTypes):
        if newIdx in matched:
            continue
        if not newNamedType.isOptional and not newNamedType.isDefaulted:
            findings.append(Finding(
                '%s.%s' % (path, newNamedType.name), INCOMPATIBLE,
                'required field was added in new schema'))


def _checkChoice(old, new, path, findings, visited):
    newByName = {}
    for namedType in new.componentType.namedTypes:
        newByName[namedType.name] = namedType

    for oldNamedType in old.componentType.namedTypes:
        fieldPath = '%s.%s' % (path, oldNamedType.name)

        newNamedType = newByName.get(oldNamedType.name)

        if newNamedType is None:
            findings.append(Finding(
                fieldPath, INCOMPATIBLE,
                'CHOICE alternative was removed in new schema'))
            continue

        _checkTypes(oldNamedType.asn1Object, newNamedType.asn1Object,
                    fieldPath, findings, visited)

    # Extra alternatives in the new schema are a compatible extension


def _checkConstraints(old, new, path, findings):
    oldKnown, oldUnknown = _splitConstraints(old.subtypeSpec)
    newKnown, newUnknown = _splitConstraints(new.subtypeSpec)

    for const in newUnknown:
        findings.append(Finding(
            path, UNKNOWN,
            'new schema constraint %r can not be analyzed' % (const,)))

    for kind in newKnown:
        oldConsts = oldKnown.get(kind)
        newConsts = newKnown[kind]

        if oldConsts is None:
            if oldUnknown:
                findings.append(Finding(
                    path, UNKNOWN,
                    'new schema adds a %s constraint; old schema has '
                    'constraints that can not be analyzed' % (kind,)))
            else:
                findings.append(Finding(
                    path, INCOMPATIBLE,
                    'new schema adds a %s constraint where old schema '
                    'is unconstrained' % (kind,)))
            continue

        covered, description = _isCovered(kind, oldConsts, newConsts)

        if covered:
            continue

        if oldUnknown:
            findings.append(Finding(
                path, UNKNOWN,
                '%s; old schema has constraints that can not be '
                'analyzed' % (description,)))
        else:
            findings.append(Finding(path, INCOMPATIBLE, description))


def _flattenConstraints(subtypeSpec):
    if subtypeSpec is None:
        return []

    if isinstance(subtypeSpec, constraint.ConstraintsIntersection):
        leaves = []
        for const in subtypeSpec:
            leaves.extend(_flattenConstraints(const))
        return leaves

    return [subtypeSpec]


def _splitConstraints(subtypeSpec):
    known = {}
    unknown = []

    for const in _flattenConstraints(subtypeSpec):
        kind = _constraintKind(const)
        if kind is None:
            unknown.append(const)
        else:
            known.setdefault(kind, []).append(const)

    return known, unknown


def _constraintKind(const):
    # Mind the inheritance: PermittedAlphabetConstraint derives from
    # SingleValueConstraint, ValueSizeConstraint from ValueRangeConstraint
    if isinstance(const, constraint.PermittedAlphabetConstraint):
        return 'permitted alphabet'
    if isinstance(const, constraint.ValueSizeConstraint):
        return 'size'
    if isinstance(const, constraint.ValueRangeConstraint):
        return 'value range'
    if isinstance(const, constraint.SingleValueConstraint):
        return 'single value'
    return None


def _isCovered(kind, oldConsts, newConsts):
    """Tell if *new* constraints admit every value *old* constraints do.

    Returns a (covered, description) pair; *description* explains the
    failure and is only meaningful when *covered* is False.
    """
    if kind in ('value range', 'size'):
        oldLo = max(const.start for const in oldConsts)
        oldHi = min(const.stop for const in oldConsts)
        newLo = max(const.start for const in newConsts)
        newHi = min(const.stop for const in newConsts)

        if oldLo > oldHi:
            # Old schema admits no values at all
            return True, ''

        covered = newLo <= oldLo and newHi >= oldHi
        description = (
            'new schema narrows the %s from %s..%s to %s..%s' % (
                kind, oldLo, oldHi, newLo, newHi))

        return covered, description

    oldValues = set(oldConsts[0])
    for const in oldConsts[1:]:
        oldValues &= set(const)

    newValues = set(newConsts[0])
    for const in newConsts[1:]:
        newValues &= set(const)

    if not oldValues:
        # Old schema admits no values at all
        return True, ''

    covered = oldValues <= newValues
    description = (
        'new schema narrows the %s constraint from %s to %s' % (
            kind, sorted(oldValues), sorted(newValues)))

    return covered, description
