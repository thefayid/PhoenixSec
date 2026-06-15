"""
RuleRegistry — centralised store for all security rules.

Rules register themselves automatically via the ``@rule`` class decorator.
The registry is a singleton — there is exactly one global instance
(``RuleRegistry.global_instance()``), but tests may create isolated
instances for isolation.

Design
------
* **Decorator pattern** — ``@rule`` decorates a class and calls
  ``RuleRegistry.register()`` at import time.
* **Language routing** — ``get_rules(language)`` returns rules whose
  ``language`` field matches *or* is ``"*"`` (language-agnostic).
* **Enabled filtering** — disabled rules (``enabled = False``) are stored
  but excluded from all query results by default.
* **Duplicate detection** — registering two rules with the same ``rule_id``
  raises ``ValueError`` immediately.

Usage
-----
::

    # Auto-register via decorator (preferred):
    from phoenixsec.rules.registry import rule

    @rule
    class MyRule(BaseRule):
        rule_id = "PY-XSS-001"
        ...

    # Manual registration:
    from phoenixsec.rules.registry import RuleRegistry
    RuleRegistry.global_instance().register(MyRule)

    # Query:
    registry = RuleRegistry.global_instance()
    python_rules = registry.get_rules("python")
    all_rules    = registry.all_rules()
    one_rule     = registry.get_by_id("PY-XSS-001")
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from phoenixsec.rules.base_rule import BaseRule

_T = TypeVar("_T", bound="type[BaseRule]")


class RuleRegistry:
    """Thread-safe registry of all available security rules.

    Instances are independent — use ``global_instance()`` to access the
    application-wide singleton, or create a new instance for isolated
    testing.

    Attributes
    ----------
    _rules:
        Internal store mapping ``rule_id`` → ``BaseRule`` class.
    _lock:
        Reentrant lock protecting concurrent registration.
    """

    # ── Singleton ──────────────────────────────────────────────────────────────

    _singleton: RuleRegistry | None = None
    _singleton_lock: threading.Lock = threading.Lock()

    @classmethod
    def global_instance(cls) -> RuleRegistry:
        """Return the application-wide singleton registry.

        Thread-safe; initialised once on first call.

        Returns
        -------
        RuleRegistry
            The global ``RuleRegistry`` instance.
        """
        if cls._singleton is None:
            with cls._singleton_lock:
                if cls._singleton is None:
                    cls._singleton = cls()
        return cls._singleton

    @classmethod
    def _reset_singleton(cls) -> None:
        """Reset the singleton — for test isolation only.

        Warning
        -------
        Never call this in production code.
        """
        with cls._singleton_lock:
            cls._singleton = None

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def __init__(self) -> None:
        # rule_id (str) → rule class (type[BaseRule])
        self._rules: dict[str, type[BaseRule]] = {}
        self._lock = threading.RLock()

    # ── Registration ───────────────────────────────────────────────────────────

    def register(self, rule_class: type[BaseRule]) -> type[BaseRule]:
        """Register a rule class in the registry.

        Can be used as a plain method call or as a class decorator
        (via the module-level ``@rule`` alias).

        Parameters
        ----------
        rule_class:
            A concrete subclass of ``BaseRule``.  The class (not an
            instance) is stored so the engine can instantiate rules fresh
            for each scan.

        Returns
        -------
        type[BaseRule]
            The same class, unchanged — enables use as a decorator.

        Raises
        ------
        TypeError
            If ``rule_class`` is not a subclass of ``BaseRule``.
        ValueError
            If a rule with the same ``rule_id`` is already registered.

        Example
        -------
        ::

            @rule
            class EvalRule(BaseRule):
                rule_id = "PY-CODE-001"
                ...
        """
        from phoenixsec.rules.base_rule import BaseRule as _BaseRule

        if not (isinstance(rule_class, type) and issubclass(rule_class, _BaseRule)):
            raise TypeError(f"Expected a BaseRule subclass, got {rule_class!r}")

        rid = rule_class.rule_id

        with self._lock:
            if rid in self._rules:
                existing = self._rules[rid].__name__
                raise ValueError(
                    f"Rule ID {rid!r} is already registered by {existing!r}. "
                    f"Each rule must have a unique rule_id."
                )
            self._rules[rid] = rule_class

        return rule_class

    def unregister(self, rule_id: str) -> None:
        """Remove a rule from the registry by its ``rule_id``.

        Silently does nothing if the rule is not registered.

        Parameters
        ----------
        rule_id:
            The ``rule_id`` of the rule to remove.
        """
        with self._lock:
            self._rules.pop(rule_id, None)

    # ── Querying ───────────────────────────────────────────────────────────────

    def get_rules(
        self,
        language: str,
        *,
        include_disabled: bool = False,
    ) -> list[type[BaseRule]]:
        """Return all rules applicable to the given language.

        A rule matches if its ``language`` attribute equals ``language``
        (case-insensitive) *or* equals ``"*"`` (language-agnostic).

        Parameters
        ----------
        language:
            Lower-case language name (e.g. ``"python"``, ``"java"``).
        include_disabled:
            When ``True``, disabled rules (``enabled = False``) are
            included.  Default: ``False``.

        Returns
        -------
        list[type[BaseRule]]
            Sorted by ``rule_id`` for deterministic ordering.
        """
        lang = language.lower()
        with self._lock:
            matches = []
            for cls in self._rules.values():
                if not (include_disabled or cls.enabled):
                    continue
                matched = False
                langs = getattr(cls, "languages", None)
                if isinstance(langs, list):
                    cls_langs = [l.lower() for l in langs]
                    if lang in cls_langs or "*" in cls_langs:
                        matched = True
                else:
                    cls_lang = getattr(cls, "language", "*")
                    if isinstance(cls_lang, str) and cls_lang.lower() in {lang, "*"}:
                        matched = True
                if matched:
                    matches.append(cls)
        return sorted(matches, key=lambda c: c.rule_id)

    def all_rules(
        self,
        *,
        include_disabled: bool = False,
    ) -> list[type[BaseRule]]:
        """Return every registered rule.

        Parameters
        ----------
        include_disabled:
            Include disabled rules when ``True``.

        Returns
        -------
        list[type[BaseRule]]
            All registered rule classes, sorted by ``rule_id``.
        """
        with self._lock:
            classes = list(self._rules.values())

        if not include_disabled:
            classes = [c for c in classes if c.enabled]

        return sorted(classes, key=lambda c: c.rule_id)

    def get_by_id(self, rule_id: str) -> type[BaseRule] | None:
        """Look up a rule by its ``rule_id``.

        Parameters
        ----------
        rule_id:
            The unique rule identifier.

        Returns
        -------
        type[BaseRule] | None
            The rule class if found, or ``None``.
        """
        with self._lock:
            return self._rules.get(rule_id)

    def languages(self) -> frozenset[str]:
        """Return the set of distinct language values among registered rules.

        Returns
        -------
        frozenset[str]
            E.g. ``frozenset({"python", "java", "*"})``.
        """
        with self._lock:
            return frozenset(cls.language.lower() for cls in self._rules.values())

    def rule_ids(self) -> frozenset[str]:
        """Return a snapshot of all registered rule IDs.

        Returns
        -------
        frozenset[str]
        """
        with self._lock:
            return frozenset(self._rules.keys())

    def is_registered(self, rule_id: str) -> bool:
        """Return ``True`` if a rule with the given ID is registered."""
        with self._lock:
            return rule_id in self._rules

    # ── Stats ──────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return a summary of registry contents.

        Returns
        -------
        dict
            Keys: ``total``, ``enabled``, ``disabled``, ``languages``.
        """
        with self._lock:
            all_cls = list(self._rules.values())

        enabled = [c for c in all_cls if c.enabled]
        disabled = [c for c in all_cls if not c.enabled]
        langs = frozenset(c.language.lower() for c in all_cls)

        return {
            "total": len(all_cls),
            "enabled": len(enabled),
            "disabled": len(disabled),
            "languages": sorted(langs),
        }

    # ── Iteration support ──────────────────────────────────────────────────────

    def __iter__(self) -> Iterator[type[BaseRule]]:
        """Iterate over all enabled rule classes."""
        yield from self.all_rules()

    def __len__(self) -> int:
        """Return the total number of registered rules (including disabled)."""
        with self._lock:
            return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        """Support ``"PY-001" in registry`` syntax."""
        return self.is_registered(rule_id)

    def __repr__(self) -> str:
        return f"RuleRegistry(total={len(self)}, languages={sorted(self.languages())})"


# ── Module-level decorator ─────────────────────────────────────────────────────


def rule(cls: _T) -> _T:
    """Class decorator that auto-registers a rule in the global registry.

    Apply this decorator to any ``BaseRule`` subclass to make it visible
    to the ``RuleEngine`` without any additional wiring.

    Parameters
    ----------
    cls:
        A concrete ``BaseRule`` subclass.

    Returns
    -------
    type[BaseRule]
        The same class, unchanged.

    Raises
    ------
    TypeError
        If ``cls`` is not a ``BaseRule`` subclass.
    ValueError
        If another rule with the same ``rule_id`` is already registered.

    Example
    -------
    ::

        @rule
        class HardcodedPasswordRule(BaseRule):
            rule_id  = "PY-SECRET-001"
            name     = "Hardcoded password"
            severity = Severity.CRITICAL
            ...
    """
    RuleRegistry.global_instance().register(cls)
    return cls
