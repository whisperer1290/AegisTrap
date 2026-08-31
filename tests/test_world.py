"""Fake-world generation, including the Section 10 synthetic-data guarantee."""

from __future__ import annotations

import re

from aegistrap.decoy.world import (
    INTERNAL_FIELDS,
    collections_for_persona,
    find_user_by_email,
    public_view,
    seed_world,
)
from aegistrap.store import StateStore

#: Domains reserved by RFC 2606 / RFC 6761 for documentation and testing.
_SAFE_SUFFIXES = (
    ".example.com",
    ".example.net",
    ".example.org",
    "example.com",
    "example.net",
    "example.org",
    ".invalid",
    ".test",
    ".localhost",
)


def _session(store: StateStore, key: str = "w"):
    session, _ = store.get_or_create_session(
        session_key=key,
        source_ip="198.51.100.4",
        user_agent="curl/8.4.0",
        world_persona="fintech",
        idle_seconds=600,
    )
    return session


def test_seeding_populates_every_collection(store: StateStore) -> None:
    session = _session(store)
    seed_world(store, session.id, "fintech")
    for collection in collections_for_persona("fintech"):
        assert store.count_objects(session.id, collection) > 0, collection


def test_seeding_is_idempotent(store: StateStore) -> None:
    session = _session(store)
    seed_world(store, session.id, "fintech")
    before = store.count_objects(session.id, "accounts")
    seed_world(store, session.id, "fintech")
    assert store.count_objects(session.id, "accounts") == before


def test_world_is_deterministic_per_session(store: StateStore) -> None:
    """A given session id must always generate the same bank.

    A world that differs between generations would contradict itself across a
    restart, which is the exact failure the state store exists to prevent.
    """
    from aegistrap.decoy.world import _seed_fintech

    session_id = "fixed-session-id-for-determinism"

    def balances(target: StateStore) -> dict[str, int]:
        _seed_fintech(target, session_id)
        return {
            o.object_id: o.data["balance_minor"]
            for o in target.list_objects(session_id, "accounts", limit=50)
        }

    first = balances(store)
    replica = StateStore(store.db_path.parent / "replica.sqlite3")
    try:
        second = balances(replica)
    finally:
        replica.close()

    assert first == second
    assert len(first) > 0


def test_different_sessions_get_different_worlds(store: StateStore) -> None:
    first, second = _session(store, key="a"), _session(store, key="b")
    seed_world(store, first.id, "fintech")
    seed_world(store, second.id, "fintech")
    balances_a = [
        o.data["balance_minor"] for o in store.list_objects(first.id, "accounts", limit=50)
    ]
    balances_b = [
        o.data["balance_minor"] for o in store.list_objects(second.id, "accounts", limit=50)
    ]
    assert balances_a != balances_b


def test_all_generated_pii_is_synthetic(store: StateStore) -> None:
    """Every identifier must be in a reserved, unroutable range (Section 10)."""
    session = _session(store)
    seed_world(store, session.id, "fintech")

    for user in store.list_objects(session.id, "users", limit=50):
        email = user.data["email"]
        assert email.endswith(_SAFE_SUFFIXES), email
        # 555-01xx is reserved for fictional use.
        assert re.fullmatch(r"\+1-555-01\d{2}", user.data["phone"]), user.data["phone"]

    for account in store.list_objects(session.id, "accounts", limit=50):
        # XX is not an assigned ISO 3166 country code, so this cannot be a real IBAN.
        assert account.data["iban"].startswith("XX"), account.data["iban"]

    for card in store.list_objects(session.id, "cards", limit=50):
        assert card.data["pan_masked"].startswith("411111")
        assert card.data["pan_full"].startswith("4111111111")

    config = store.get_object(session.id, "config", "runtime")
    assert ".test" in config.data["database_url"]


def test_public_view_hides_internal_fields_by_default(store: StateStore) -> None:
    session = _session(store)
    seed_world(store, session.id, "fintech")
    user = store.list_objects(session.id, "users", limit=1)[0]

    hidden = public_view("users", user.data)
    for field in INTERNAL_FIELDS["users"]:
        assert field not in hidden

    leaked = public_view("users", user.data, leak_internal=True)
    assert "password_hash" in leaked
    assert leaked["password_hash"] == user.data["password_hash"]


def test_generated_emails_are_unique(store: StateStore) -> None:
    """Colliding emails would authenticate the wrong row on login."""
    session = _session(store)
    seed_world(store, session.id, "fintech")
    emails = [u.data["email"] for u in store.list_objects(session.id, "users", limit=50)]
    assert len(emails) == len(set(emails))


def test_user_lookup_is_case_insensitive(store: StateStore) -> None:
    session = _session(store)
    seed_world(store, session.id, "fintech")
    user = store.list_objects(session.id, "users", limit=1)[0]
    found = find_user_by_email(store, session.id, user.data["email"].upper())
    assert found is not None
    assert found["id"] == user.data["id"]
    assert find_user_by_email(store, session.id, "nobody@example.com") is None


def test_ecommerce_persona_seeds_its_own_collections(store: StateStore) -> None:
    session = _session(store, key="shop")
    seed_world(store, session.id, "ecommerce")
    assert store.count_objects(session.id, "products") > 0
    assert store.count_objects(session.id, "orders") > 0
    assert store.count_objects(session.id, "accounts") == 0
