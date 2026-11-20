"""Opt-in explanation boundary, not an LLM client or an action executor.

A provider is trusted application code, not a Python sandbox. It receives a fresh
numeric-only summary; its returned model text is untrusted and never dispatched.
This module performs no network, environment, key, file or process operations.
"""
from __future__ import annotations
from copy import deepcopy
from decimal import Decimal, InvalidOperation
import re
from typing import Any, Callable

MAX_FINDINGS = 8
MAX_TEXT_CHARS = 4096
MAX_EXPLANATION_CHARS = 4096
_CAPACITY_IDS = frozenset(("physical_memory", "commit", "gpu_memory"))
_UNKNOWN_IDS = frozenset(("node_oom", "port_conflict", "gpu_allocation", "background_anomaly", "hard_faults"))
_FINDING_FIELDS = frozenset(("id", "conclusion", "state", "confidenceBasis", "evidence", "unknowns", "nextSteps"))
_EVIDENCE_FIELDS = frozenset(("metric", "value", "unit", "source"))
_METRIC_UNITS = {"used": "GB", "capacity": "GB", "ratio": "%", "threshold": "%", "sample_start": "ms", "sample_end": "ms"}
_DECIMAL = re.compile(r"[0-9]+(?:\.[0-9]+)?\Z", re.ASCII)


class BoundaryError(ValueError):
    """A fixed safe error message, never raw findings or provider output."""


def _text(value: Any) -> bool:
    return type(value) is str and len(value) <= MAX_TEXT_CHARS


def _numeric(metric: str, value: Any) -> float:
    if type(value) is not str or len(value) > 32 or not _DECIMAL.fullmatch(value):
        raise BoundaryError("Invalid numeric evidence")
    try:
        number = Decimal(value)
    except InvalidOperation:
        raise BoundaryError("Invalid numeric evidence") from None
    limit = Decimal(100) if metric in ("ratio", "threshold") else Decimal(2**64 - 1) if metric.startswith("sample_") else Decimal(10**9)
    if not number.is_finite() or number < 0 or number > limit:
        raise BoundaryError("Numeric evidence outside supported range")
    if metric.startswith("sample_") and "." in value:
        raise BoundaryError("Invalid sample timestamp")
    return float(number)


def _validate_and_summarize(findings: Any) -> list[dict[str, Any]]:
    if type(findings) is not list or len(findings) > MAX_FINDINGS:
        raise BoundaryError("Invalid deterministic findings collection")
    seen_ids: set[str] = set()
    summary: list[dict[str, Any]] = []
    for finding in findings:
        if type(finding) is not dict or set(finding) != _FINDING_FIELDS:
            raise BoundaryError("Unsupported finding fields")
        identifier, state = finding["id"], finding["state"]
        if type(identifier) is not str or identifier not in _CAPACITY_IDS | _UNKNOWN_IDS or identifier in seen_ids:
            raise BoundaryError("Unsupported or duplicate finding ID")
        seen_ids.add(identifier)
        if type(state) is not str or state not in ("observed", "risk", "unknown"):
            raise BoundaryError("Unsupported finding state")
        if identifier in _UNKNOWN_IDS and state != "unknown":
            raise BoundaryError("Unsupported detector cannot claim a diagnosis")
        confidence = finding["confidenceBasis"]
        if type(confidence) is not str or confidence not in ("none", "directMeasurement", "heuristic"):
            raise BoundaryError("Unsupported confidence basis")
        if not _text(finding["conclusion"]):
            raise BoundaryError("Invalid local-only finding text")
        for field in ("unknowns", "nextSteps"):
            value = finding[field]
            if type(value) is not list or len(value) > 16 or not all(_text(item) for item in value):
                raise BoundaryError("Invalid local-only finding text")
        evidence = finding["evidence"]
        if type(evidence) is not list or len(evidence) > 6:
            raise BoundaryError("Invalid evidence collection")
        numeric: list[dict[str, Any]] = []
        seen_metrics: set[str] = set()
        for item in evidence:
            if type(item) is not dict or set(item) != _EVIDENCE_FIELDS:
                raise BoundaryError("Unsupported evidence fields")
            metric = item["metric"]
            if type(metric) is not str or metric not in _METRIC_UNITS or metric in seen_metrics:
                raise BoundaryError("Unsupported or duplicate evidence metric")
            seen_metrics.add(metric)
            if type(item["unit"]) is not str or item["unit"] != _METRIC_UNITS[metric] or not _text(item["source"]):
                raise BoundaryError("Unsupported evidence unit or source")
            value = _numeric(metric, item["value"])
            if identifier in _UNKNOWN_IDS:
                raise BoundaryError("Unsupported detector cannot supply numeric diagnosis evidence")
            # Even monotonic timestamps stay local. No PID, path, source, raw log,
            # conclusion, next-step text or confidence prose crosses this boundary.
            if metric in ("used", "capacity", "ratio", "threshold"):
                numeric.append({"metric": metric, "value": value, "unit": _METRIC_UNITS[metric]})
        summary.append({"id": identifier, "state": state, "metrics": numeric})
    return summary


def explain_findings(findings: Any, *, enabled: bool = False,
                     provider: Callable[[dict[str, Any]], str] | None = None) -> dict[str, Any]:
    """Return untouched deterministic facts plus a separately labeled explanation.

    enabled=True is application opt-in to a caller-supplied callback, not permission
    to configure a remote service or transmit data. No provider ships with this API.
    """
    if type(enabled) is not bool:
        raise BoundaryError("Explicit boolean opt-in is required")
    summary = _validate_and_summarize(findings)
    result: dict[str, Any] = {
        "schemaVersion": 1, "facts": deepcopy(findings), "status": "disabled",
        "untrustedExplanation": None, "explanationTrusted": False, "writeAuthorized": False,
    }
    if not enabled:
        return result
    if not callable(provider):
        raise BoundaryError("No explicit provider callback configured")
    request = {"schemaVersion": 1, "purpose": "explain_only_not_diagnose_or_authorize",
               "findings": deepcopy(summary)}
    try:
        explanation = provider(request)
    except Exception:
        result["status"] = "providerError"
        result["error"] = "Explanation provider failed; deterministic facts unchanged"
        return result
    if type(explanation) is not str or not explanation.strip() or len(explanation) > MAX_EXPLANATION_CHARS:
        result["status"] = "providerError"
        result["error"] = "Explanation output rejected; deterministic facts unchanged"
        return result
    result["status"] = "explained"
    result["untrustedExplanation"] = explanation
    return result
