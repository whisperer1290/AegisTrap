"""Fake-world generation for the decoy API.

Every value here is synthetic, per Section 10 of the synopsis. Concretely:

* e-mail domains come from RFC 2606 reserved TLDs (``example.com``, ``.invalid``),
* telephone numbers use the 555-01xx range reserved for fictional use,
* IBAN-like strings start with ``XX``, which is not an assigned country code,
* card numbers are masked and built from the 4111 test prefix,
* no value is derived from any real customer record.

The world is generated deterministically from the session ID, so a given
session always sees the same fake bank, and a replayed evaluation run is
reproducible, while different attackers see different data.
"""

from __future__ import annotations

import hashlib
import random
import time
from typing import Any

from aegistrap.store import StateStore

# --- synthetic vocabulary ---------------------------------------------------

_FIRST_NAMES = (
    "Adaeze",
    "Mira",
    "Tomas",
    "Ingrid",
    "Rahul",
    "Solene",
    "Ewan",
    "Nadia",
    "Kofi",
    "Beatriz",
    "Joon",
    "Halima",
    "Lasse",
    "Priya",
    "Emil",
    "Yara",
)
_LAST_NAMES = (
    "Okafor",
    "Lindqvist",
    "Duarte",
    "Halvorsen",
    "Bhatnagar",
    "Marchetti",
    "Whitcombe",
    "Zayed",
    "Mensah",
    "Sorokina",
    "Park",
    "Al-Rashid",
    "Vermeulen",
    "Iyer",
    "Novak",
    "Haddad",
)
_MERCHANTS = (
    "Kestrel Grocers",
    "Northline Rail",
    "Blue Ibis Cafe",
    "Vantage Fuel",
    "Orchard Pharmacy",
    "Meridian Books",
    "Halcyon Fitness",
    "Torvald Hardware",
    "Cinder & Sons",
    "Lumen Utilities",
    "Ardent Insurance",
    "Waypoint Travel",
    "Stonebridge Rent",
    "Cobalt Telecom",
    "Fernway Clinic",
)
_CITIES = (
    "Rotterdam",
    "Tallinn",
    "Porto",
    "Bergen",
    "Pune",
    "Turin",
    "Bristol",
    "Amman",
    "Accra",
    "Vilnius",
    "Busan",
    "Valencia",
)
_TXN_CATEGORIES = (
    "groceries",
    "transport",
    "dining",
    "fuel",
    "health",
    "retail",
    "utilities",
    "insurance",
    "travel",
    "rent",
    "telecom",
    "transfer",
)
_WEAK_PASSWORDS = (
    "Summer2024!",
    "Password123",
    "letmein",
    "Welcome1",
    "qwerty123",
    "northwind",
    "Spring2025!",
    "admin123",
)
_ROLES = ("customer", "customer", "customer", "customer", "support", "analyst")

_PRODUCTS = (
    ("Aurora Desk Lamp", "home", 4900),
    ("Trailhead Backpack 32L", "outdoor", 12900),
    ("Cirrus Wireless Earbuds", "audio", 8900),
    ("Kettle & Co Pour-Over Set", "kitchen", 3400),
    ("Solstice Running Shoe", "footwear", 10900),
    ("Nimbus Mechanical Keyboard", "computing", 15900),
    ("Fernway Yoga Mat", "fitness", 4200),
    ("Halcyon Sleep Mask", "wellness", 1900),
)


def _rng_for(session_id: str) -> random.Random:
    seed = int(hashlib.sha256(session_id.encode()).hexdigest()[:16], 16)
    return random.Random(seed)


def _fake_iban(rng: random.Random) -> str:
    # XX is not an assigned ISO 3166 country code, so this can never collide
    # with a real IBAN.
    return (
        "XX"
        + "".join(str(rng.randint(0, 9)) for _ in range(2))
        + "NWCB"
        + "".join(str(rng.randint(0, 9)) for _ in range(10))
    )


def _fake_phone(rng: random.Random) -> str:
    return f"+1-555-01{rng.randint(10, 99)}"


def _email(first: str, last: str, rng: random.Random, unique: str) -> str:
    # The numeric suffix is required: first-initial + surname is not unique
    # across 12 users, and a colliding email makes login authenticate the
    # wrong row (and fail) — a state contradiction of the kind Section 13
    # exists to prevent.
    domain = rng.choice(("example.com", "example.net", "mail.invalid"))
    local = first[0].lower() + "." + last.lower().replace("-", "").replace(" ", "")
    return f"{local}.{unique}@{domain}"


# --- field visibility -------------------------------------------------------

#: Fields that a correctly-implemented API would never serialise. They exist in
#: the state store so that the EXCESSIVE_DATA_EXPOSURE weakness has something
#: real to leak, and so the leak stays consistent across a session.
INTERNAL_FIELDS: dict[str, tuple[str, ...]] = {
    "users": (
        "password_hash",
        "password_plaintext",
        "risk_score",
        "internal_notes",
        "aml_flags",
        "session_token_seed",
    ),
    "accounts": (
        "ledger_shard",
        "internal_notes",
        "overdraft_authorised_by",
        "risk_band",
    ),
    "transactions": ("fraud_score", "processor_ref", "internal_notes"),
    "cards": ("pan_full", "cvv"),
    "api_keys": ("secret",),
    "products": ("cost_minor", "supplier_ref"),
    "orders": ("margin_minor", "internal_notes"),
}


def public_view(
    collection: str, data: dict[str, Any], *, leak_internal: bool = False
) -> dict[str, Any]:
    """Serialise a world object the way the decoy API would expose it."""
    if leak_internal:
        return dict(data)
    hidden = INTERNAL_FIELDS.get(collection, ())
    return {k: v for k, v in data.items() if k not in hidden}


# --- seeding ----------------------------------------------------------------


def seed_world(store: StateStore, session_id: str, persona: str = "fintech") -> None:
    """Populate a session's fake world. Idempotent per session."""
    session = store.get_session(session_id)
    if session is not None and session.world_seeded:
        return
    if persona == "ecommerce":
        _seed_ecommerce(store, session_id)
    else:
        _seed_fintech(store, session_id)
    store.mark_world_seeded(session_id)


def _seed_fintech(store: StateStore, session_id: str) -> None:
    rng = _rng_for(session_id)
    now = time.time()

    n_users = 12
    first_account_id = 1001
    user_ids: list[str] = []

    for i in range(n_users):
        first = _FIRST_NAMES[(rng.randrange(len(_FIRST_NAMES)) + i) % len(_FIRST_NAMES)]
        last = _LAST_NAMES[(rng.randrange(len(_LAST_NAMES)) + i) % len(_LAST_NAMES)]
        user_id = f"usr_{2000 + i}"
        user_ids.append(user_id)
        role = "admin" if i == 0 else rng.choice(_ROLES)
        plaintext = rng.choice(_WEAK_PASSWORDS)
        store.put_object(
            session_id,
            "users",
            user_id,
            {
                "id": user_id,
                "email": _email(first, last, rng, unique=str(i)),
                "full_name": f"{first} {last}",
                "role": role,
                "status": "active" if rng.random() > 0.12 else "suspended",
                "mfa_enabled": rng.random() > 0.7,
                "phone": _fake_phone(rng),
                "city": rng.choice(_CITIES),
                "kyc_status": rng.choice(("verified", "verified", "pending")),
                "created_at": _iso(now - rng.randint(200, 1400) * 86400),
                # internal-only, see INTERNAL_FIELDS
                "password_hash": "$2b$12$"
                + hashlib.sha256(f"{user_id}{plaintext}".encode()).hexdigest()[:31],
                "password_plaintext": plaintext,
                "risk_score": round(rng.uniform(0.01, 0.86), 3),
                "internal_notes": rng.choice(
                    (
                        "Escalated to compliance 2024-11; cleared.",
                        "Requested limit increase, pending review.",
                        "No adverse findings.",
                        "Device change flagged, resolved by support.",
                    )
                ),
                "aml_flags": [] if rng.random() > 0.2 else ["velocity_review"],
            },
            owner_id=user_id,
            sensitive=True,
        )

    account_ids: list[str] = []
    for i in range(14):
        account_id = str(first_account_id + i)
        owner = user_ids[i % len(user_ids)]
        currency = rng.choice(("EUR", "EUR", "USD", "GBP"))
        balance = rng.randint(1_20_00, 94_500_00)
        account_ids.append(account_id)
        store.put_object(
            session_id,
            "accounts",
            account_id,
            {
                "id": account_id,
                "owner_id": owner,
                "iban": _fake_iban(rng),
                "product": rng.choice(("checking", "savings", "checking", "credit_line")),
                "currency": currency,
                "balance_minor": balance,
                "available_minor": max(0, balance - rng.randint(0, 40_00)),
                "status": "open" if rng.random() > 0.08 else "frozen",
                "opened_at": _iso(now - rng.randint(120, 2200) * 86400),
                "ledger_shard": f"eu-w1-shard-{rng.randint(1, 8)}",
                "internal_notes": "Standard retail account.",
                "overdraft_authorised_by": rng.choice(("", "", "ops_desk_2")),
                "risk_band": rng.choice(("A", "B", "B", "C")),
            },
            owner_id=owner,
        )

    for account_id in account_ids:
        account = store.get_object(session_id, "accounts", account_id)
        if account is None:
            continue
        currency = account.data["currency"]
        for _ in range(rng.randint(6, 13)):
            txn_id = f"txn_{rng.randrange(16**10):010x}"
            direction = rng.choice(("debit", "debit", "debit", "credit"))
            amount = (
                rng.randint(3_50, 2_400_00)
                if direction == "debit"
                else rng.randint(50_00, 6_500_00)
            )
            merchant = rng.choice(_MERCHANTS)
            store.put_object(
                session_id,
                "transactions",
                txn_id,
                {
                    "id": txn_id,
                    "account_id": account_id,
                    "direction": direction,
                    "amount_minor": amount,
                    "currency": currency,
                    "counterparty_name": merchant if direction == "debit" else "Payroll BV",
                    "counterparty_iban": _fake_iban(rng),
                    "category": rng.choice(_TXN_CATEGORIES),
                    "status": rng.choice(("booked", "booked", "booked", "pending")),
                    "booked_at": _iso(now - rng.randint(1, 90) * 86400),
                    "description": f"{merchant} {rng.choice(_CITIES)}",
                    "fraud_score": round(rng.uniform(0.0, 0.31), 3),
                    "processor_ref": f"PSP-{rng.randrange(16**8):08x}",
                    "internal_notes": "",
                },
                owner_id=account.data["owner_id"],
            )

        if rng.random() > 0.45:
            card_id = f"crd_{rng.randrange(16**8):08x}"
            last4 = f"{rng.randint(0, 9999):04d}"
            store.put_object(
                session_id,
                "cards",
                card_id,
                {
                    "id": card_id,
                    "account_id": account_id,
                    "brand": rng.choice(("visa", "mastercard")),
                    "pan_masked": f"411111******{last4}",
                    "expiry": f"{rng.randint(1, 12):02d}/{rng.randint(27, 31)}",
                    "status": rng.choice(("active", "active", "blocked")),
                    # test-range PAN, deliberately not a valid live number
                    "pan_full": f"4111111111{last4}11",
                    "cvv": f"{rng.randint(100, 999)}",
                },
                owner_id=account.data["owner_id"],
                sensitive=True,
            )

    # Planted credentials (HONEY_CREDENTIALS bait). These are the only "secrets"
    # in the system and they authenticate to nothing real.
    for name, scopes in (
        ("payments-gateway", ["payments:write", "accounts:read"]),
        ("reporting-etl", ["accounts:read", "transactions:read"]),
        ("legacy-batch", ["*"]),
    ):
        key_id = f"ak_{hashlib.sha1(f'{session_id}{name}'.encode()).hexdigest()[:12]}"
        store.put_object(
            session_id,
            "api_keys",
            key_id,
            {
                "id": key_id,
                "name": name,
                "prefix": key_id[:8],
                "scopes": scopes,
                "created_at": _iso(now - rng.randint(30, 900) * 86400),
                "last_used_at": _iso(now - rng.randint(1, 20) * 86400),
                "secret": "nwcb_sk_live_"
                + hashlib.sha256(f"{session_id}{name}secret".encode()).hexdigest()[:32],
            },
            sensitive=True,
        )

    store.put_object(
        session_id,
        "config",
        "runtime",
        {
            "service": "northwind-core-api",
            "version": "2.4.1",
            "commit": hashlib.sha1(session_id.encode()).hexdigest()[:10],
            "environment": "production",
            "region": "eu-west-1",
            "database_url": "postgresql://nwcb_app@pg-core-01.internal.nwcb.test:5432/core",
            "redis_url": "redis://cache-01.internal.nwcb.test:6379/2",
            "ledger_service": "http://ledger-internal.nwcb.test:8080",
            "feature_flags": {
                "instant_transfers": True,
                "legacy_v0_routes": True,
                "graphql_introspection": True,
                "strict_object_authz": False,
            },
            "build_time": _iso(now - 9 * 86400),
        },
        sensitive=True,
    )

    store.next_counter(session_id, "accounts", start=first_account_id + 13)


def _seed_ecommerce(store: StateStore, session_id: str) -> None:
    rng = _rng_for(session_id)
    now = time.time()

    user_ids: list[str] = []
    for i in range(10):
        first = _FIRST_NAMES[(rng.randrange(len(_FIRST_NAMES)) + i) % len(_FIRST_NAMES)]
        last = _LAST_NAMES[(rng.randrange(len(_LAST_NAMES)) + i) % len(_LAST_NAMES)]
        user_id = f"usr_{3000 + i}"
        user_ids.append(user_id)
        plaintext = rng.choice(_WEAK_PASSWORDS)
        store.put_object(
            session_id,
            "users",
            user_id,
            {
                "id": user_id,
                "email": _email(first, last, rng, unique=str(i)),
                "full_name": f"{first} {last}",
                "role": "admin" if i == 0 else "customer",
                "status": "active",
                "mfa_enabled": rng.random() > 0.8,
                "phone": _fake_phone(rng),
                "city": rng.choice(_CITIES),
                "loyalty_tier": rng.choice(("bronze", "silver", "gold")),
                "created_at": _iso(now - rng.randint(30, 900) * 86400),
                "password_hash": "$2b$12$"
                + hashlib.sha256(f"{user_id}{plaintext}".encode()).hexdigest()[:31],
                "password_plaintext": plaintext,
                "risk_score": round(rng.uniform(0.0, 0.4), 3),
                "internal_notes": "",
                "aml_flags": [],
            },
            owner_id=user_id,
            sensitive=True,
        )

    for idx, (name, category, price) in enumerate(_PRODUCTS):
        product_id = str(5001 + idx)
        store.put_object(
            session_id,
            "products",
            product_id,
            {
                "id": product_id,
                "name": name,
                "category": category,
                "price_minor": price,
                "currency": "EUR",
                "stock": rng.randint(0, 240),
                "rating": round(rng.uniform(3.2, 4.9), 1),
                "cost_minor": int(price * rng.uniform(0.38, 0.62)),
                "supplier_ref": f"SUP-{rng.randrange(16**6):06x}",
            },
        )

    for i in range(16):
        order_id = str(9001 + i)
        owner = user_ids[i % len(user_ids)]
        items = rng.sample(range(len(_PRODUCTS)), rng.randint(1, 3))
        total = sum(_PRODUCTS[j][2] for j in items)
        store.put_object(
            session_id,
            "orders",
            order_id,
            {
                "id": order_id,
                "user_id": owner,
                "status": rng.choice(("delivered", "shipped", "processing", "cancelled")),
                "total_minor": total,
                "currency": "EUR",
                "items": [
                    {"product_id": str(5001 + j), "name": _PRODUCTS[j][0], "qty": 1} for j in items
                ],
                "shipping_city": rng.choice(_CITIES),
                "placed_at": _iso(now - rng.randint(1, 200) * 86400),
                "margin_minor": int(total * rng.uniform(0.15, 0.4)),
                "internal_notes": "",
            },
            owner_id=owner,
        )

    store.put_object(
        session_id,
        "config",
        "runtime",
        {
            "service": "northwind-shop-api",
            "version": "3.1.0",
            "commit": hashlib.sha1(session_id.encode()).hexdigest()[:10],
            "environment": "production",
            "region": "eu-west-1",
            "database_url": "mysql://shop_app@mysql-01.internal.nwcb.test:3306/shop",
            "feature_flags": {
                "legacy_v0_routes": True,
                "graphql_introspection": True,
                "strict_object_authz": False,
            },
            "build_time": _iso(now - 4 * 86400),
        },
        sensitive=True,
    )
    store.next_counter(session_id, "orders", start=9016)


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def find_user_by_email(store: StateStore, session_id: str, email: str) -> dict[str, Any] | None:
    for obj in store.list_objects(session_id, "users", limit=200):
        if str(obj.data.get("email", "")).lower() == email.lower():
            return obj.data
    return None


def collections_for_persona(persona: str) -> tuple[str, ...]:
    if persona == "ecommerce":
        return ("users", "products", "orders", "config")
    return ("users", "accounts", "transactions", "cards", "api_keys", "config")
