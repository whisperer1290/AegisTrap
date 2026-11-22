"""Fingerprint evasion: stable within a session, varied across sessions."""

from __future__ import annotations

from aegistrap.evasion import _BANNER_PROFILES, FingerprintMutator


def _mutator(**kwargs: object) -> FingerprintMutator:
    defaults: dict[str, object] = {
        "enabled": True,
        "service_name": "Northwind Capital API",
        "base_latency_floor_ms": 40,
        "base_latency_jitter_ms": 90,
        "epoch_seconds": 3600,
        "seed": "test-seed",
    }
    defaults.update(kwargs)
    return FingerprintMutator(**defaults)  # type: ignore[arg-type]


def test_disabled_mutator_presents_one_stable_banner() -> None:
    mutator = FingerprintMutator(enabled=False, banner="nginx")
    first = mutator.response_headers("session-a", seq=1)
    second = mutator.response_headers("session-b", seq=9)
    assert first["server"] == "nginx"
    assert second["server"] == "nginx"


def test_the_default_banner_never_names_the_real_runtime() -> None:
    """Announcing uvicorn would identify the honeypot as a Python service."""
    assert (
        "uvicorn"
        not in FingerprintMutator(enabled=False).response_headers("s", seq=1)["server"].lower()
    )
    for profile in _BANNER_PROFILES:
        assert "uvicorn" not in profile["server"].lower()


def test_banner_is_stable_across_a_session() -> None:
    """A Server header that changes mid-session is more obviously fake than
    one that never changes at all."""
    mutator = _mutator()
    banners = {
        mutator.response_headers("session-a", seq=seq).get("server", "") for seq in range(1, 30)
    }
    assert len(banners) == 1


def test_latency_profile_is_stable_across_a_session() -> None:
    mutator = _mutator()
    profiles = {mutator.latency_profile("session-a") for _ in range(10)}
    assert len(profiles) == 1


def test_different_sessions_see_different_servers() -> None:
    mutator = _mutator()
    banners = {
        mutator.response_headers(f"session-{index}", seq=1).get("server", "") for index in range(60)
    }
    assert len(banners) > 3


def test_epochs_change_the_fingerprint() -> None:
    """A fingerprint harvested today must not identify the deployment later."""
    mutator = _mutator(epoch_seconds=3600)
    early = mutator.fingerprint_for("session-a", now=0.0)
    later = mutator.fingerprint_for("session-a", now=100 * 3600.0)
    assert early.epoch != later.epoch
    assert (early.banner, early.optional_headers) != (later.banner, later.optional_headers)


def test_per_request_headers_vary_without_changing_the_identity() -> None:
    mutator = _mutator()
    first = mutator.response_headers("session-a", seq=1)
    second = mutator.response_headers("session-a", seq=2)
    assert first.get("server") == second.get("server")
    varying = {k for k in first if first.get(k) != second.get(k)}
    assert varying <= {
        "x-request-id",
        "x-served-by",
        "x-cache",
        "x-runtime",
        "x-correlation-id",
        "x-envoy-upstream-service-time",
        "cf-ray",
            "x-amz-request-id",
            "x-powered-by",
        }


def test_no_empty_header_values_are_emitted() -> None:
    mutator = _mutator()
    for index in range(40):
        headers = mutator.response_headers(f"s{index}", seq=index)
        assert all(value for value in headers.values()), headers
        assert all(name and name == name.lower() for name in headers)


def test_latency_floor_stays_in_a_plausible_range() -> None:
    mutator = _mutator(base_latency_floor_ms=40, base_latency_jitter_ms=90)
    for index in range(50):
        floor, jitter = mutator.latency_profile(f"s{index}")
        assert 20 <= floor <= 80, floor
        assert 40 <= jitter <= 190, jitter


def test_epoch_seconds_has_a_sane_floor() -> None:
    # Rotating faster than a minute would change appearance mid-session.
    assert _mutator(epoch_seconds=1).epoch_seconds >= 60


def test_describe_reports_the_configuration() -> None:
    described = _mutator().describe()
    assert described["enabled"] is True
    assert described["banner_pool_size"] == len(_BANNER_PROFILES)
    assert "current_epoch" in described


def test_evasion_is_off_by_default(settings) -> None:
    """It is the Section 4 stretch goal, so it must be opt-in."""
    assert settings.fingerprint_evasion is False
