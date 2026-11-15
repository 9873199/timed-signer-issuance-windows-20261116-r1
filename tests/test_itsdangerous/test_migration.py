import json
import threading
from dataclasses import FrozenInstanceError
from datetime import datetime
from datetime import timezone

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadPayload
from itsdangerous.exc import BadSignature
from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.migration import MigratingTimedSerializer
from itsdangerous.migration import SigningScheme
from itsdangerous.migration import URLSafeMigratingTimedSerializer

UTC = timezone.utc


def at(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, tz=UTC)


class ManualClock:
    """Deterministic clock recording how often it was read."""

    def __init__(self, now: int) -> None:
        self.now = now
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return float(self.now)


class CountingSerializer:
    """Data serializer that records every deserialization attempt."""

    def __init__(self) -> None:
        self.loads_count = 0
        self.dumps_count = 0

    def dumps(self, obj: object) -> str:
        self.dumps_count += 1
        return json.dumps(obj, separators=(",", ":"))

    def loads(self, payload: str) -> object:
        self.loads_count += 1
        return json.loads(payload)


class ExplodingSerializer(CountingSerializer):
    def loads(self, payload: str) -> object:
        super().loads(payload)
        raise ValueError("payload deliberately unreadable")


def make_old_scheme(**overrides: object) -> SigningScheme:
    kwargs: dict[str, object] = dict(
        id="old",
        secret_key="old-key",
        salt="old-salt",
        valid_from=1000,
        valid_to=2000,
        retire_at=3000,
    )
    kwargs.update(overrides)
    return SigningScheme(**kwargs)  # type: ignore[arg-type]


def make_new_scheme(**overrides: object) -> SigningScheme:
    kwargs: dict[str, object] = dict(
        id="new",
        secret_key="new-key",
        salt="new-salt",
        valid_from=1500,
        valid_to=5000,
        retire_at=6000,
    )
    kwargs.update(overrides)
    return SigningScheme(**kwargs)  # type: ignore[arg-type]


def make_migrator(
    clock: ManualClock | None = None,
    *,
    schemes: list[SigningScheme] | None = None,
    current_scheme: str = "new",
    serializer: object | None = None,
) -> MigratingTimedSerializer[object]:
    if schemes is None:
        schemes = [make_old_scheme(), make_new_scheme()]

    return MigratingTimedSerializer(
        schemes,
        current_scheme,
        clock=clock or ManualClock(2500),
        serializer=serializer,  # type: ignore[arg-type]
    )


def make_token(migrator: MigratingTimedSerializer[object], obj: object, ts: int) -> str:
    """Produce a real signature whose embedded timestamp is ``ts``."""
    with freeze_time(at(ts)):
        return migrator.dumps(obj)


class TestConfiguration:
    def test_empty_schemes_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            MigratingTimedSerializer([], "old", clock=ManualClock(0))

    def test_schemes_must_be_a_sequence(self) -> None:
        scheme = make_old_scheme()

        with pytest.raises(TypeError, match="sequence"):
            MigratingTimedSerializer(iter([scheme]), "old", clock=ManualClock(0))  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="sequence"):
            MigratingTimedSerializer("old", "old", clock=ManualClock(0))  # type: ignore[arg-type]

    def test_scheme_elements_must_be_schemes(self) -> None:
        with pytest.raises(TypeError, match="SigningScheme"):
            MigratingTimedSerializer([object()], "old", clock=ManualClock(0))  # type: ignore[list-item]

    def test_duplicate_ids_rejected(self) -> None:
        with pytest.raises(ValueError, match="unique"):
            MigratingTimedSerializer(
                [make_old_scheme(), make_new_scheme(id="old")],
                "old",
                clock=ManualClock(0),
            )

    def test_inverted_window_rejected(self) -> None:
        with pytest.raises(ValueError, match="inverted"):
            make_old_scheme(valid_from=2000, valid_to=2000)

        with pytest.raises(ValueError, match="inverted"):
            make_old_scheme(valid_from=2001, valid_to=2000)

    def test_retirement_before_window_end_rejected(self) -> None:
        with pytest.raises(ValueError, match="retires"):
            make_old_scheme(valid_to=2000, retire_at=1999)

    def test_unknown_current_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="current_scheme"):
            MigratingTimedSerializer(
                [make_old_scheme()], "missing", clock=ManualClock(0)
            )

    def test_wrong_clock_type_rejected(self) -> None:
        with pytest.raises(TypeError, match="clock"):
            MigratingTimedSerializer(
                [make_old_scheme()],
                "old",
                clock=123,  # type: ignore[arg-type]
            )

    def test_scheme_id_must_be_nonempty_str(self) -> None:
        with pytest.raises(TypeError, match="id"):
            make_old_scheme(id="")

        with pytest.raises(TypeError, match="id"):
            make_old_scheme(id=42)  # type: ignore[arg-type]

    def test_window_bounds_must_be_real_ints(self) -> None:
        with pytest.raises(TypeError):
            make_old_scheme(valid_from=1000.0)  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            make_old_scheme(valid_to=True)  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            make_old_scheme(retire_at=3000.5)  # type: ignore[arg-type]

    def test_scheme_is_frozen(self) -> None:
        scheme = make_old_scheme()

        with pytest.raises(FrozenInstanceError):
            scheme.valid_from = 5  # type: ignore[misc]

    def test_signer_kwargs_are_frozen(self) -> None:
        scheme = make_old_scheme(signer_kwargs={"key_derivation": "hmac"})

        with pytest.raises(TypeError):
            scheme.signer_kwargs["key_derivation"] = "concat"  # type: ignore[index]

    def test_caller_list_cannot_change_configured_schemes(self) -> None:
        schemes = [make_old_scheme(), make_new_scheme()]
        migrator = make_migrator(schemes=schemes)

        schemes.append(make_new_scheme(id="third"))

        assert len(migrator.schemes) == 2

        with pytest.raises(TypeError):
            migrator.schemes[0] = make_new_scheme(id="third")  # type: ignore[index]

    def test_repr_and_result_never_expose_key_material(self) -> None:
        scheme = make_old_scheme()
        migrator = make_migrator()

        assert "old-key" not in repr(scheme)
        assert "old-key" not in repr(migrator)
        assert "redacted" in repr(scheme)

        token = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()], "old", clock=ManualClock(2500)
            ),
            {"v": 1},
            1500,
        )
        _payload, scheme_id = migrator.loads_migration(token)
        assert scheme_id == "old"
        assert "key" not in scheme_id


class TestVerificationWithRealSignatures:
    def test_old_token_issued_before_retirement_verifies(self) -> None:
        migrator = make_migrator()
        token = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()], "old", clock=ManualClock(2500)
            ),
            {"user": "alice"},
            1500,
        )

        payload, scheme_id = migrator.loads_migration(token)

        assert payload == {"user": "alice"}
        assert scheme_id == "old"

    def test_old_key_forging_post_window_timestamp_is_rejected(self) -> None:
        # Attacker holds the old key and signs fresh data with a current
        # timestamp; the signature is genuine but the time is outside the
        # old scheme's issuance window.
        migrator = make_migrator(clock=ManualClock(2500))
        forged = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()], "old", clock=ManualClock(2500)
            ),
            {"user": "attacker"},
            2500,
        )

        with pytest.raises(BadTimeSignature, match="issuance window"):
            migrator.loads_migration(forged)

    def test_backdated_old_token_after_retirement_is_rejected(self) -> None:
        # A correctly backdated old-scheme token must not verify once the
        # read happens at or after the retirement instant.
        migrator = make_migrator(clock=ManualClock(3000))
        token = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()], "old", clock=ManualClock(3000)
            ),
            {"user": "alice"},
            1500,
        )

        with pytest.raises(BadSignature):
            migrator.loads_migration(token)

        # One second before retirement it still verifies.
        migrator_early = make_migrator(clock=ManualClock(2999))
        assert migrator_early.loads_migration(token) == ({"user": "alice"}, "old")

    def test_retirement_instant_itself_is_unavailable(self) -> None:
        token = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()], "old", clock=ManualClock(3000)
            ),
            "x",
            1500,
        )

        make_migrator(clock=ManualClock(2999)).loads_migration(token)

        with pytest.raises(BadSignature):
            make_migrator(clock=ManualClock(3000)).loads_migration(token)

    def test_issuance_window_endpoints_are_half_open(self) -> None:
        old_only = MigratingTimedSerializer(
            [make_old_scheme()], "old", clock=ManualClock(2500)
        )

        # valid_from is inclusive.
        token_at_start = make_token(old_only, "x", 1000)
        assert old_only.loads_migration(token_at_start) == ("x", "old")

        # Any interior second works.
        token_inside = make_token(old_only, "x", 1999)
        assert old_only.loads_migration(token_inside) == ("x", "old")

        # valid_to is exclusive.
        token_at_end = make_token(old_only, "x", 2000)
        with pytest.raises(BadTimeSignature, match="issuance window"):
            old_only.loads_migration(token_at_end)

    def test_future_timestamp_rejected_with_tolerance_boundary(self) -> None:
        migrator = make_migrator(clock=ManualClock(2500))
        future_token = make_token(migrator, "x", 2510)

        with pytest.raises(SignatureExpired):
            migrator.loads_migration(future_token)

        with pytest.raises(SignatureExpired):
            migrator.loads_migration(future_token, future_tolerance=9)

        # Equality is accepted: ts == now + tolerance.
        assert migrator.loads_migration(future_token, future_tolerance=10) == (
            "x",
            "new",
        )

    def test_max_age_boundary(self) -> None:
        # Old token at ts=1500 read at 2500 has an age of exactly 1000.
        migrator = make_migrator(clock=ManualClock(2500))
        token = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()], "old", clock=ManualClock(2500)
            ),
            "x",
            1500,
        )

        assert migrator.loads_migration(token, max_age=1000) == ("x", "old")

        with pytest.raises(SignatureExpired):
            migrator.loads_migration(token, max_age=999)

    def test_invalid_age_arguments_rejected(self) -> None:
        migrator = make_migrator()
        token = make_token(migrator, "x", 2500)

        with pytest.raises(ValueError):
            migrator.loads_migration(token, max_age=-1)

        with pytest.raises(ValueError):
            migrator.loads_migration(token, future_tolerance=-1)

    def test_shared_key_with_different_salts_cannot_cross_verify(self) -> None:
        scheme_a = SigningScheme(
            id="a",
            secret_key="shared-key",
            salt="salt-a",
            valid_from=1000,
            valid_to=4000,
            retire_at=5000,
        )
        scheme_b = SigningScheme(
            id="b",
            secret_key="shared-key",
            salt="salt-b",
            valid_from=1000,
            valid_to=4000,
            retire_at=5000,
        )
        signer_a = MigratingTimedSerializer([scheme_a], "a", clock=ManualClock(2000))
        migrator = MigratingTimedSerializer(
            [scheme_a, scheme_b], "a", clock=ManualClock(2000)
        )

        token = make_token(signer_a, {"secret": 42}, 1500)

        # Only the scheme whose salt actually signed it can verify it.
        assert migrator.loads_migration(token) == ({"secret": 42}, "a")

        signer_b_only = MigratingTimedSerializer(
            [scheme_b], "b", clock=ManualClock(2000)
        )
        with pytest.raises(BadSignature):
            signer_b_only.loads_migration(token)

    def test_overlapping_schemes_first_complete_match_wins(self) -> None:
        # Same key and salt, overlapping windows: either signer verifies
        # the signature, so ordering decides which id is reported.
        first = SigningScheme(
            id="first",
            secret_key="shared",
            salt="same",
            valid_from=1000,
            valid_to=3000,
            retire_at=4000,
        )
        second = SigningScheme(
            id="second",
            secret_key="shared",
            salt="same",
            valid_from=2000,
            valid_to=5000,
            retire_at=6000,
        )
        migrator = MigratingTimedSerializer(
            [first, second], "second", clock=ManualClock(2500)
        )
        token = make_token(migrator, "x", 2500)

        assert migrator.loads_migration(token) == ("x", "first")

    def test_timestamp_from_one_scheme_never_combines_with_another_key(self) -> None:
        # Scheme "first" does not cover ts=2500; "second" does. There is
        # no path where first's signature check passes and second's window
        # gets reused: each scheme must satisfy the whole contract itself.
        first = SigningScheme(
            id="first",
            secret_key="shared",
            salt="same",
            valid_from=1000,
            valid_to=2000,
            retire_at=4000,
        )
        second = SigningScheme(
            id="second",
            secret_key="shared",
            salt="same",
            valid_from=2000,
            valid_to=5000,
            retire_at=6000,
        )
        migrator = MigratingTimedSerializer(
            [first, second], "second", clock=ManualClock(2500)
        )

        token_in_second = make_token(migrator, "x", 2500)
        assert migrator.loads_migration(token_in_second) == ("x", "second")

        token_in_first = make_token(migrator, "x", 1500)
        assert migrator.loads_migration(token_in_first) == ("x", "first")

        # A tampered token fails every scheme outright.
        tampered = token_in_second[:-1] + ("A" if token_in_second[-1] != "A" else "B")
        with pytest.raises(BadSignature):
            migrator.loads_migration(tampered)

    def test_tampered_token_rejected(self) -> None:
        migrator = make_migrator()
        token = make_token(migrator, "x", 2500)
        tampered = token.replace("x", "y", 1)

        with pytest.raises(BadSignature):
            migrator.loads_migration(tampered)

    def test_clock_is_read_exactly_once_per_read(self) -> None:
        clock = ManualClock(2500)
        migrator = make_migrator(clock=clock)
        token = make_token(migrator, "x", 2500)

        assert clock.calls == 0
        migrator.loads_migration(token)
        assert clock.calls == 1
        migrator.loads_migration(token)
        assert clock.calls == 2

    def test_two_migrators_share_one_snapshot_per_read(self) -> None:
        clock = ManualClock(2500)
        migrator_a = make_migrator(clock=clock)
        migrator_b = make_migrator(
            clock=clock, schemes=[make_new_scheme()], current_scheme="new"
        )
        token = make_token(migrator_a, {"v": 1}, 2500)

        result_a, id_a = migrator_a.loads_migration(token)
        result_b, id_b = migrator_b.loads_migration(token)

        assert (result_a, id_a) == ({"v": 1}, "new")
        assert (result_b, id_b) == ({"v": 1}, "new")
        # Each migrator took its own single snapshot; both saw the same
        # immutable "now".
        assert clock.calls == 2

        clock.now = 2510
        future_token = make_token(migrator_a, "x", 2510)
        assert migrator_a.loads_migration(future_token) == ("x", "new")

    def test_injected_clock_is_independent_of_global_time(self) -> None:
        clock = ManualClock(2500)
        migrator = make_migrator(clock=clock)
        token = make_token(migrator, "x", 2500)

        # Freezing the process-global clock must not redirect the
        # migrator's injected clock.
        with freeze_time("1980-01-01"):
            assert migrator.loads_migration(token) == ("x", "new")

    def test_dumps_only_uses_the_current_scheme(self) -> None:
        migrator = make_migrator(current_scheme="new")
        token = make_token(migrator, {"v": 1}, 2500)

        _payload, scheme_id = migrator.loads_migration(token)
        assert scheme_id == "new"

        old_only = MigratingTimedSerializer(
            [make_old_scheme()], "old", clock=ManualClock(2500)
        )
        with pytest.raises(BadSignature):
            old_only.loads_migration(token)

    def test_urlsafe_migrator_roundtrip_including_compression(self) -> None:
        clock = ManualClock(2500)
        migrator = URLSafeMigratingTimedSerializer(
            [make_old_scheme(), make_new_scheme()], "new", clock=clock
        )

        small = make_token(migrator, {"v": 1}, 2500)
        assert migrator.loads_migration(small) == ({"v": 1}, "new")

        # Repetitive payload is large enough to take the zlib branch.
        large = make_token(migrator, {"blob": "z" * 500}, 2500)
        payload, scheme_id = migrator.loads_migration(large)
        assert payload == {"blob": "z" * 500}
        assert scheme_id == "new"

    def test_concurrent_reads_never_swap_object_state(self) -> None:
        clock = ManualClock(2500)
        migrator = make_migrator(clock=clock)
        token = make_token(migrator, "x", 2500)
        clock_identity = migrator.clock

        errors: list[BaseException] = []

        def worker() -> None:
            try:
                for _ in range(25):
                    payload, scheme_id = migrator.loads_migration(token)
                    assert payload == "x"
                    assert scheme_id == "new"
            except BaseException as exc:  # pragma: no cover - failure reporting
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert clock.calls == 16 * 25
        assert migrator.clock is clock_identity

    def test_legacy_single_key_entry_points_are_unsupported(self) -> None:
        migrator = make_migrator()

        with pytest.raises(NotImplementedError):
            migrator.loads("whatever")

        with pytest.raises(NotImplementedError):
            migrator.make_signer()

        with pytest.raises(NotImplementedError):
            migrator.loads_unsafe("whatever")

    def test_dumps_rejects_salt_override(self) -> None:
        migrator = make_migrator()

        with pytest.raises(ValueError, match="salt"):
            migrator.dumps("x", salt="other")

    def test_all_schemes_retired_raises_without_deserializing(self) -> None:
        serializer = CountingSerializer()
        migrator = make_migrator(serializer=serializer, clock=ManualClock(6000))
        token = make_token(migrator, "x", 2500)

        with pytest.raises(BadSignature):
            migrator.loads_migration(token)

        assert serializer.loads_count == 0

    def test_bytes_input_roundtrips(self) -> None:
        migrator = make_migrator(clock=ManualClock(2500))
        token = make_token(migrator, "x", 2500)

        payload, scheme_id = migrator.loads_migration(token.encode("ascii"))

        assert payload == "x"
        assert scheme_id == "new"


class TestPayloadIsNotDeserializedUnlessTimeAndSignaturePass:
    def test_bad_signature_never_deserializes(self) -> None:
        serializer = CountingSerializer()
        migrator = make_migrator(serializer=serializer)
        token = make_token(migrator, {"v": 1}, 2500)
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

        with pytest.raises(BadSignature):
            migrator.loads_migration(tampered)

        assert serializer.loads_count == 0

    def test_outside_window_never_deserializes(self) -> None:
        serializer = CountingSerializer()
        migrator = make_migrator(serializer=serializer)
        # Signed with the old key at a time the old window does not cover.
        forged = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()],
                "old",
                clock=ManualClock(2500),
                serializer=serializer,
            ),
            {"v": 1},
            2500,
        )

        with pytest.raises(BadTimeSignature):
            migrator.loads_migration(forged)

        assert serializer.loads_count == 0

    def test_future_timestamp_never_deserializes(self) -> None:
        serializer = CountingSerializer()
        migrator = make_migrator(serializer=serializer, clock=ManualClock(2500))
        future_token = make_token(migrator, {"v": 1}, 2505)

        with pytest.raises(SignatureExpired):
            migrator.loads_migration(future_token)

        assert serializer.loads_count == 0

    def test_expired_max_age_never_deserializes(self) -> None:
        serializer = CountingSerializer()
        migrator = make_migrator(serializer=serializer, clock=ManualClock(2500))
        token = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()],
                "old",
                clock=ManualClock(2500),
                serializer=serializer,
            ),
            {"v": 1},
            1500,
        )

        with pytest.raises(SignatureExpired):
            migrator.loads_migration(token, max_age=10)

        assert serializer.loads_count == 0

    def test_retired_scheme_never_deserializes(self) -> None:
        serializer = CountingSerializer()
        migrator = make_migrator(serializer=serializer, clock=ManualClock(3000))
        token = make_token(
            MigratingTimedSerializer(
                [make_old_scheme()],
                "old",
                clock=ManualClock(3000),
                serializer=serializer,
            ),
            {"v": 1},
            1500,
        )

        with pytest.raises(BadSignature):
            migrator.loads_migration(token)

        assert serializer.loads_count == 0

    def test_successful_read_deserializes_exactly_once(self) -> None:
        serializer = CountingSerializer()
        migrator = make_migrator(serializer=serializer)
        token = make_token(migrator, {"v": 1}, 2500)

        payload, scheme_id = migrator.loads_migration(token)

        assert payload == {"v": 1}
        assert scheme_id == "new"
        assert serializer.loads_count == 1

    def test_bad_payload_only_reached_after_all_checks_pass(self) -> None:
        serializer = ExplodingSerializer()
        migrator = make_migrator(serializer=serializer)
        token = make_token(migrator, {"v": 1}, 2500)

        with pytest.raises(BadPayload):
            migrator.loads_migration(token)

        # The deserializer was invoked: signature and time passed first.
        assert serializer.loads_count == 1
