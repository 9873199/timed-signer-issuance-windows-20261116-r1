.. module:: itsdangerous.migration

Migrating Between Signing Schemes
=================================

Retiring a signing key is not the same as accepting the old key for a
few more days. Anyone who held the old key can use it during that grace
period to sign *new* data and stamp it with the current time. To make
retirement safe, verification must constrain not just which key is
accepted, but **which issuance timestamps that key is allowed to
prove**.

:class:`MigratingTimedSerializer` takes an immutable list of
:class:`SigningScheme` objects. Each scheme binds a secret key and salt
(plus optional signer parameters) to:

-   the half-open issuance window ``[valid_from, valid_to)`` in which
    that scheme was allowed to produce signatures, and
-   ``retire_at``, the instant at which verification with that scheme
    stops. The retirement instant itself is not accepted.

A scheme can only authenticate a timestamp that was verified with *that
scheme's own key and salt* and that lies inside *that scheme's own*
issuance window. A timestamp recovered from one scheme can never be
combined with another scheme's key; each candidate must satisfy the
whole contract on its own.

.. code-block:: python

    from itsdangerous import MigratingTimedSerializer, SigningScheme

    serializer = MigratingTimedSerializer(
        schemes=[
            SigningScheme(
                id="v1",
                secret_key="old-secret",
                salt="cookie-session",
                valid_from=1_500_000_000,
                valid_to=1_600_000_000,
                retire_at=1_601_000_000,
            ),
            SigningScheme(
                id="v2",
                secret_key="new-secret",
                salt="cookie-session",
                valid_from=1_600_000_000,
                valid_to=1_700_000_000,
                retire_at=1_701_000_000,
            ),
        ],
        current_scheme="v2",
    )

    token = serializer.dumps({"user_id": 1})
    payload, scheme_id = serializer.loads_migration(token)

    if scheme_id != "v2":
        # The data verified under an older scheme; re-sign it now so the
        # old token can be discarded once that scheme retires.
        token = serializer.dumps(payload)

Configuration errors are rejected when the serializer is built: an
inverted issuance window, duplicate or empty scheme ids, an empty
scheme list, an unknown current scheme, or a clock that is not a
zero-argument callable. The scheme list is copied into a tuple and
each scheme is immutable, so configuration cannot change underneath a
running reader.

Verification rules
------------------

Every check in one call to :meth:`~MigratingTimedSerializer.loads_migration`
uses a single snapshot of the injected clock, which is read exactly
once:

1.  Schemes with ``now >= retire_at`` are skipped before the input is
    inspected.
2.  The signature and embedded timestamp must verify under the
    scheme's own signer. Unverified content never influences which
    scheme is tried.
3.  The verified timestamp must fall in ``[valid_from, valid_to)``;
    ``valid_from`` is accepted and ``valid_to`` is rejected.
4.  A timestamp more than ``future_tolerance`` seconds ahead of ``now``
    is rejected; an exact tie is accepted.
5.  When ``max_age`` is given, ``now - timestamp > max_age`` is
    rejected; an exact tie is accepted.

The business payload is deserialized only after one scheme passes every
check. If schemes overlap, the first scheme in the configured order that
fully satisfies the contract wins, and its id is returned alongside the
payload. Secret key material is never returned and never appears in
:func:`repr`.

New signatures are always produced with the single ``current_scheme``;
a retired scheme can never issue again. The existing
:class:`~itsdangerous.TimedSerializer` and
:class:`~itsdangerous.URLSafeTimedSerializer` are unchanged.

.. autoclass:: SigningScheme
    :members:

.. autoclass:: MigratingTimedSerializer
    :members:

.. autoclass:: URLSafeMigratingTimedSerializer
    :members:
