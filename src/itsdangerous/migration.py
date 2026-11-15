from __future__ import annotations

import collections.abc as cabc
import time
import typing as t
from dataclasses import dataclass
from dataclasses import field
from types import MappingProxyType

from .encoding import want_bytes
from .exc import BadSignature
from .exc import BadTimeSignature
from .exc import SignatureExpired
from .serializer import _PDataSerializer
from .serializer import _TSerialized
from .serializer import is_text_serializer
from .serializer import Serializer
from .signer import Signer
from .timed import TimestampSigner
from .url_safe import URLSafeSerializerMixin


class ClockProtocol(t.Protocol):
    """A zero-argument callable returning the current time as seconds
    since the epoch (as :func:`time.time` does).

    The clock is injected so that a single read can take one immutable
    snapshot of "now" and tests can run against a fixed time.
    """

    def __call__(self) -> float: ...


@dataclass(frozen=True, kw_only=True)
class SigningScheme:
    """One signing scheme allowed by a :class:`MigratingTimedSerializer`.

    The scheme is immutable once constructed. It binds one secret key and
    salt (plus any signer parameters) to the *issuance window* in which
    that scheme was allowed to produce signatures, and to the moment at
    which verification with that scheme must stop.

    :param id: Unique, non-empty identifier returned on a successful
        read so the caller can decide whether to re-sign the data.
    :param secret_key: Secret key (or list of keys) for this scheme.
    :param salt: Salt combined with the secret key; two schemes sharing
        a key but using different salts produce distinct signatures.
    :param valid_from: Inclusive lower bound of the half-open issuance
        window ``[valid_from, valid_to)``, in epoch seconds.
    :param valid_to: Exclusive upper bound of the issuance window, in
        epoch seconds. A timestamp equal to ``valid_to`` is rejected.
    :param retire_at: Verification deadline, in epoch seconds. At
        ``retire_at`` itself the scheme is no longer used, so it must be
        at least ``valid_to``.
    :param signer_kwargs: Extra parameters forwarded to the signer
        class, such as ``key_derivation`` or ``digest_method``.

    .. versionadded:: 2.3.0
    """

    id: str
    secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes]
    salt: str | bytes
    valid_from: int
    valid_to: int
    retire_at: int
    signer_kwargs: cabc.Mapping[str, t.Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise TypeError("SigningScheme.id must be a non-empty str")

        for name in ("valid_from", "valid_to", "retire_at"):
            value = getattr(self, name)

            # bool is a subclass of int, but it is never a valid timestamp.
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"SigningScheme.{name} must be an int timestamp")

        if self.valid_from >= self.valid_to:
            raise ValueError(
                f"SigningScheme {self.id!r} has an inverted issuance window:"
                f" valid_from ({self.valid_from}) must be < valid_to"
                f" ({self.valid_to})"
            )

        if self.retire_at < self.valid_to:
            raise ValueError(
                f"SigningScheme {self.id!r} retires at {self.retire_at}, which"
                " is before its issuance window ends at"
                f" {self.valid_to}; retire_at must be >= valid_to"
            )

        if not isinstance(self.signer_kwargs, cabc.Mapping):
            raise TypeError("SigningScheme.signer_kwargs must be a mapping")

        # Freeze the mapping so callers cannot mutate a configured scheme.
        object.__setattr__(
            self, "signer_kwargs", MappingProxyType(dict(self.signer_kwargs))
        )

    def __repr__(self) -> str:
        # Never expose key material in logs or tracebacks.
        return (
            f"SigningScheme(id={self.id!r}, salt={self.salt!r},"
            f" valid_from={self.valid_from}, valid_to={self.valid_to},"
            f" retire_at={self.retire_at},"
            f" signer_kwargs={dict(self.signer_kwargs)!r},"
            " secret_key=<redacted>)"
        )


class MigratingTimedSerializer(Serializer[_TSerialized]):
    """Verify timed signatures against an immutable list of signing
    schemes, each restricted to the time window in which it was allowed
    to issue signatures.

    Unlike a plain "accept the old key for N more days" rule, a scheme
    can only authenticate an embedded timestamp that (a) was verified
    with *that scheme's* key and salt, and (b) lies inside that
    scheme's own issuance window. A reader holding a retired key
    therefore cannot backdate new data into a still-accepted window,
    and a timestamp recovered from one scheme can never be combined
    with another scheme's key: each candidate must satisfy the whole
    contract on its own.

    :param schemes: Non-empty sequence of :class:`SigningScheme`
        objects, kept in the given order. The sequence is copied into a
        tuple, so later mutation of the caller's list has no effect.
        Scheme ids must be unique.
    :param current_scheme: Id of the only scheme used by
        :meth:`dumps`; it must identify one of ``schemes``.
    :param clock: Injected zero-argument clock. It is called exactly
        once per :meth:`loads_migration` call, and every check in that
        read uses the same snapshot.
    :param serializer: Object with ``dumps``/``loads`` used for the
        payload, as on :class:`~itsdangerous.serializer.Serializer`.
    :param serializer_kwargs: Keyword arguments for ``serializer.dumps``.
    :param signer: :class:`~itsdangerous.timed.TimestampSigner` subclass
        to instantiate per scheme.

    The verification rules, all evaluated against the single clock
    snapshot of the read:

    1.  Schemes with ``now >= retire_at`` are skipped; the retirement
        instant itself is unavailable.
    2.  The signature and embedded timestamp are verified with the
        scheme's own signer. Nothing about the unverified input can
        pick a scheme or influence ordering.
    3.  The verified timestamp must be in the half-open issuance window
        ``[valid_from, valid_to)``: ``valid_from`` is accepted,
        ``valid_to`` is rejected.
    4.  A timestamp more than ``future_tolerance`` seconds ahead of
        ``now`` is rejected; ``ts == now + future_tolerance`` is
        accepted.
    5.  When ``max_age`` is given, ``now - ts > max_age`` is rejected;
        equal ages are accepted, matching :class:`TimestampSigner`.

    The payload body is deserialized only after every check has passed
    for one scheme. Overlapping schemes may both match a token; the
    first scheme in ``schemes`` that fully satisfies the contract wins.

    .. versionadded:: 2.3.0
    """

    default_signer: type[TimestampSigner] = TimestampSigner  # pyright: ignore

    def __init__(
        self,
        schemes: cabc.Sequence[SigningScheme],
        current_scheme: str,
        *,
        clock: ClockProtocol = time.time,
        serializer: _PDataSerializer[t.Any] | None = None,
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[TimestampSigner] | None = None,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be a zero-argument callable returning a time")

        if isinstance(schemes, (str, bytes)) or not isinstance(schemes, cabc.Sequence):
            raise TypeError("schemes must be a non-empty sequence of SigningScheme")

        if len(schemes) == 0:
            raise ValueError("at least one SigningScheme is required")

        for scheme in schemes:
            if not isinstance(scheme, SigningScheme):
                raise TypeError("every item of schemes must be a SigningScheme")

        scheme_ids = [scheme.id for scheme in schemes]

        if len(set(scheme_ids)) != len(scheme_ids):
            raise ValueError("SigningScheme ids must be unique")

        if not isinstance(current_scheme, str) or current_scheme not in scheme_ids:
            raise ValueError(
                "current_scheme must be the id of one of the configured schemes"
            )

        if serializer is None:
            serializer = self.default_serializer

        if signer is None:
            signer = self.default_signer

        # Payload machinery inherited from Serializer. Scheme signers do
        # not use the single-key attributes, which are kept empty.
        self.serializer: _PDataSerializer[_TSerialized] = serializer
        self.is_text_serializer: bool = is_text_serializer(serializer)
        self.serializer_kwargs: dict[str, t.Any] = serializer_kwargs or {}
        # Keep the base class annotation; the local ``signer`` below is
        # still known to produce TimestampSigner instances.
        self.signer: type[Signer] = signer
        self.secret_keys: list[bytes] = []
        self.salt: bytes | None = None
        self.signer_kwargs: dict[str, t.Any] = {}
        self.fallback_signers: list[t.Any] = []

        self.clock: ClockProtocol = clock
        self._current_id: str = current_scheme
        self._schemes: tuple[SigningScheme, ...] = tuple(schemes)
        self._entries: tuple[tuple[SigningScheme, TimestampSigner], ...] = tuple(
            (
                scheme,
                signer(
                    scheme.secret_key,
                    salt=scheme.salt,
                    **scheme.signer_kwargs,
                ),
            )
            for scheme in self._schemes
        )
        self._entries_by_id: dict[str, tuple[SigningScheme, TimestampSigner]] = {
            scheme.id: entry
            for entry, scheme in zip(self._entries, self._schemes, strict=True)
        }

    @property
    def schemes(self) -> tuple[SigningScheme, ...]:
        """The immutable tuple of configured schemes."""
        return self._schemes

    @property
    def current_scheme(self) -> SigningScheme:
        """The scheme used by :meth:`dumps`."""
        return self._entries_by_id[self._current_id][0]

    def dumps(self, obj: t.Any, salt: str | bytes | None = None) -> _TSerialized:
        """Sign ``obj`` using the current scheme only.

        The embedded timestamp comes from the signer's own
        :meth:`~TimestampSigner.get_timestamp`; no retired scheme can
        ever be used to produce new signatures. The salt is bound by
        each :class:`SigningScheme`, so passing ``salt`` here is an
        error rather than a silently different signature.
        """
        if salt is not None:
            raise ValueError(
                "salt is configured per SigningScheme and cannot be"
                " overridden for a single dump"
            )

        signer = self._entries_by_id[self._current_id][1]
        payload = want_bytes(self.dump_payload(obj))
        rv = signer.sign(payload)

        if self.is_text_serializer:
            return t.cast(_TSerialized, rv.decode("utf-8"))

        return t.cast(_TSerialized, rv)

    def loads_migration(
        self,
        s: str | bytes,
        *,
        max_age: int | None = None,
        future_tolerance: int = 0,
    ) -> tuple[t.Any, str]:
        """Verify ``s`` against every configured scheme.

        :param s: The signed value to verify.
        :param max_age: Optional maximum accepted age in seconds. An age
            equal to ``max_age`` is accepted.
        :param future_tolerance: Non-negative number of seconds the
            embedded timestamp may be ahead of the clock snapshot.
        :return: ``(payload, scheme_id)`` where ``scheme_id`` identifies
            the scheme that fully satisfied the contract. Key material
            is never part of the return value.
        :raises BadSignature: If no scheme can verify the token, or no
            scheme passes all the time checks.
        """
        if max_age is not None and (
            not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 0
        ):
            raise ValueError("max_age must be a non-negative int or None")

        if (
            not isinstance(future_tolerance, int)
            or isinstance(future_tolerance, bool)
            or future_tolerance < 0
        ):
            raise ValueError("future_tolerance must be a non-negative int")

        data = want_bytes(s)
        # One clock read per call: every check below shares this value,
        # so a scheme cannot be selected against a moving "now".
        now = int(self.clock())
        last_exception: BadSignature | None = None
        # A scheme whose signature verified but whose time policy failed
        # is more informative than a scheme that could not verify at all;
        # remember it separately so later signature failures cannot
        # overwrite it.
        last_policy_exception: BadTimeSignature | None = None

        for scheme, signer in self._entries:
            # Rule 1: retirement is decided before touching the input.
            if now >= scheme.retire_at:
                continue

            # Rule 2: the signature (and timestamp) must verify under
            # this scheme's own key and salt first.
            try:
                payload, date_signed = signer.unsign(
                    data, max_age=None, return_timestamp=True
                )
            except BadSignature as err:
                last_exception = err
                continue

            timestamp = int(date_signed.timestamp())

            # Rule 3: half-open issuance window of the same scheme.
            if not scheme.valid_from <= timestamp < scheme.valid_to:
                last_policy_exception = BadTimeSignature(
                    f"Signature timestamp {timestamp} is outside the issuance"
                    f" window [{scheme.valid_from}, {scheme.valid_to}) of"
                    f" scheme {scheme.id!r}",
                    payload=payload,
                    date_signed=date_signed,
                )
                continue

            # Rule 4: future skew. Equality is accepted.
            if timestamp > now + future_tolerance:
                last_policy_exception = SignatureExpired(
                    f"Signature age {now - timestamp} < {-future_tolerance} seconds",
                    payload=payload,
                    date_signed=date_signed,
                )
                continue

            # Rule 5: caller-required maximum age. Equality is accepted.
            if max_age is not None and now - timestamp > max_age:
                last_policy_exception = SignatureExpired(
                    f"Signature age {now - timestamp} > {max_age} seconds",
                    payload=payload,
                    date_signed=date_signed,
                )
                continue

            # Only now, with one scheme having passed every check, is
            # the business payload allowed to be deserialized.
            return self.load_payload(payload), scheme.id

        if last_policy_exception is not None:
            raise last_policy_exception

        if last_exception is None:
            last_exception = BadSignature("no usable signing scheme")

        raise last_exception

    # The single-key/salt entry points from Serializer cannot apply to a
    # list of schemes. Fail loudly instead of silently using empty keys.
    def make_signer(self, salt: str | bytes | None = None) -> t.NoReturn:
        raise NotImplementedError(
            "signers are managed per SigningScheme; use 'dumps' and"
            " 'loads_migration' instead"
        )

    def iter_unsigners(
        self, salt: str | bytes | None = None
    ) -> cabc.Iterator[t.NoReturn]:
        raise NotImplementedError(
            "signers are managed per SigningScheme; use 'loads_migration' instead"
        )

    def loads(
        self, s: str | bytes, salt: str | bytes | None = None, **kwargs: t.Any
    ) -> t.NoReturn:
        raise NotImplementedError("use 'loads_migration' on a migrating serializer")

    def loads_unsafe(
        self, s: str | bytes, salt: str | bytes | None = None
    ) -> t.NoReturn:
        raise NotImplementedError("use 'loads_migration' on a migrating serializer")


class URLSafeMigratingTimedSerializer(
    URLSafeSerializerMixin, MigratingTimedSerializer[str]
):
    """Works like :class:`MigratingTimedSerializer` but dumps and loads
    a URL safe string, like
    :class:`~itsdangerous.url_safe.URLSafeTimedSerializer`.

    .. versionadded:: 2.3.0
    """
