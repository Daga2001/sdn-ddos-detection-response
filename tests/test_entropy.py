import math

from sdn_ddos.detection.entropy import (
    AdaptiveBand,
    EntropyDetector,
    FlowObservation,
    shannon_entropy,
)


def normal_window() -> list:
    # three hosts talking to three peers, similar rates -> high entropy
    return [
        FlowObservation("10.0.1.1", "10.0.1.2", 30.0),
        FlowObservation("10.0.1.2", "10.0.1.3", 28.0),
        FlowObservation("10.0.1.3", "10.0.1.1", 32.0),
    ]


def flood_window() -> list:
    # one source saturating one victim on top of background chatter
    return [*normal_window(), FlowObservation("10.0.1.1", "10.0.1.3", 900.0)]


def warmed_detector(**overrides) -> EntropyDetector:
    detector = EntropyDetector(warmup_windows=5, **overrides)
    for _ in range(5):
        assert detector.observe(1, normal_window()).reason == "warmup"
    return detector


def test_shannon_entropy_uniform_and_degenerate():
    assert shannon_entropy([1, 1, 1, 1]) == 2.0
    assert shannon_entropy([5]) == 0.0
    assert shannon_entropy([]) == 0.0
    assert shannon_entropy([0, 0]) == 0.0
    assert math.isclose(shannon_entropy([1, 1]), 1.0)


def test_adaptive_band_learns_mean_and_respects_min_std():
    band = AdaptiveBand(alpha=0.5, k=3.0, min_std=0.1, warmup=2)
    assert not band.ready
    band.update(1.0)
    band.update(1.0)
    assert band.ready
    assert band.mean == 1.0
    assert band.std == 0.1
    assert math.isclose(band.lower, 0.7)
    assert math.isclose(band.upper, 1.3)


def test_idle_window_is_not_evaluated_and_resets_streak():
    detector = warmed_detector()
    result = detector.observe(1, [FlowObservation("a", "b", 1.0)])
    assert not result.evaluated
    assert result.reason == "idle"


def test_normal_traffic_after_warmup_is_not_suspicious():
    detector = warmed_detector()
    result = detector.observe(1, normal_window())
    assert result.evaluated
    assert not result.suspicious
    assert not result.confirmed


def test_flood_needs_two_consecutive_windows_to_confirm():
    detector = warmed_detector()
    first = detector.observe(1, flood_window())
    assert first.suspicious and not first.confirmed and first.consecutive == 1
    second = detector.observe(1, flood_window())
    assert second.confirmed and second.consecutive == 2
    assert second.target_dst == "10.0.1.3"
    assert second.candidates == ("10.0.1.1",)


def test_single_suspicious_window_followed_by_normal_does_not_confirm():
    detector = warmed_detector()
    assert detector.observe(1, flood_window()).suspicious
    recovered = detector.observe(1, normal_window())
    assert not recovered.suspicious and recovered.consecutive == 0
    assert not detector.observe(1, flood_window()).confirmed


def test_suspicious_windows_do_not_poison_the_baseline():
    detector = warmed_detector()
    detector.observe(1, flood_window())
    detector.observe(1, flood_window())
    detector.observe(1, flood_window())
    assert detector.observe(1, flood_window()).confirmed
    assert not detector.observe(1, normal_window()).suspicious


def test_switches_keep_independent_state():
    detector = warmed_detector()
    fresh = detector.observe(2, normal_window())
    assert fresh.reason == "warmup"


def test_spoofed_sources_raise_source_entropy_and_are_flagged():
    detector = warmed_detector()
    spoofed = normal_window() + [
        FlowObservation(f"172.16.0.{i}", "10.0.1.3", 40.0) for i in range(1, 60)
    ]
    result = detector.observe(1, spoofed)
    assert result.suspicious
    assert result.h_src is not None and result.src_upper is not None
    assert result.h_src > result.src_upper


def test_from_env_reads_overrides():
    detector = EntropyDetector.from_env(
        {
            "SDN_ENTROPY_K": "4",
            "SDN_ENTROPY_CONSECUTIVE": "3",
            "SDN_ENTROPY_WARMUP": "7",
        }
    )
    assert detector.k == 4.0
    assert detector.consecutive_windows == 3
    assert detector.warmup_windows == 7


def victim_reply_window() -> list:
    # a SYN flood: the attacker's flow plus the victim's RST replies, which are
    # flows whose SOURCE is the victim
    return [
        *normal_window(),
        FlowObservation("10.0.1.9", "10.0.1.3", 800.0),
        FlowObservation("10.0.1.3", "10.0.1.9", 700.0),
    ]


def test_the_victim_is_never_listed_as_a_candidate_even_with_heavy_replies():
    detector = warmed_detector()
    detector.observe(1, victim_reply_window())
    result = detector.observe(1, victim_reply_window())
    assert result.confirmed
    assert result.target_dst == "10.0.1.3"
    # the victim carries well over 30 % of the rate as a source, yet is excluded
    assert "10.0.1.3" not in result.candidates
    assert result.candidates == ("10.0.1.9",)
