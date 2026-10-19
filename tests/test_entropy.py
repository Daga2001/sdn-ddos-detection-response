import math

import pytest

from sdn_ddos.detection.entropy import (
    AdaptiveBand,
    EntropyDetector,
    FlowObservation,
    RollingBand,
    YuBand,
    entropy_of,
    entropy_panel,
    format_signal,
    mean_rates,
    merge_switch_rates,
    shannon_entropy,
    window_state,
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


def many_attackers_window() -> list:
    # seven sources each sending 300 pkt/s to one victim: each holds ~12 % of the rate
    return [
        *normal_window(),
        *[FlowObservation(f"10.0.1.{20 + i}", "10.0.1.3", 300.0) for i in range(7)],
    ]


def test_every_source_of_a_many_to_one_flood_is_named_not_only_a_single_flooder():
    detector = warmed_detector()
    detector.observe(1, many_attackers_window())
    result = detector.observe(1, many_attackers_window())
    assert result.confirmed and result.target_dst == "10.0.1.3"
    assert set(result.candidates) == {f"10.0.1.{20 + i}" for i in range(7)}
    # the quiet background hosts are still never accused
    assert not {"10.0.1.1", "10.0.1.2"} & set(result.candidates)


def quiet_window() -> list:
    # what is left after the attacker was blocked: one chatty client in a trickle
    return [FlowObservation("10.0.1.5", "10.0.1.6", 6.0)]


def test_a_quiet_window_never_names_a_candidate_even_when_the_alarm_stays_on():
    detector = warmed_detector(min_total_rate=2.0)
    detector.observe(1, quiet_window())
    result = detector.observe(1, quiet_window())
    assert result.confirmed  # the distribution is still outside the learned band
    # ...but 6 pkt/s is not a flood: a 100 % share of a trickle is not enough
    assert result.candidates == ()


def test_the_candidate_rate_floor_is_configurable():
    detector = warmed_detector(min_total_rate=2.0, candidate_min_rate=5.0)
    detector.observe(1, quiet_window())
    assert detector.observe(1, quiet_window()).candidates == ("10.0.1.5",)
    assert (
        EntropyDetector.from_env(
            {"SDN_ENTROPY_CANDIDATE_MIN_RATE": "7"}
        ).candidate_min_rate
        == 7.0
    )
    assert EntropyDetector.from_env({}).candidate_min_rate == 20.0


def test_hold_keeps_the_onset_of_a_flood_out_of_the_baseline():
    detector = warmed_detector(update_hold=2)
    band = detector._states[1].src
    learned = band.count
    assert not detector.observe(1, normal_window()).suspicious
    assert band.count == learned  # still waiting to see what follows
    assert detector.observe(1, flood_window()).suspicious
    assert band.count == learned  # the pending normal-looking window was discarded
    for _ in range(3):
        detector.observe(1, normal_window())
    assert band.count == learned + 1  # later windows are learned, two behind


def test_no_hold_updates_the_baseline_immediately():
    detector = warmed_detector()
    band = detector._states[1].src
    learned = band.count
    detector.observe(1, normal_window())
    assert band.count == learned + 1


def test_slower_smoothing_after_warmup_moves_the_band_less():
    fast = AdaptiveBand(alpha=0.5, k=3.0, min_std=0.1, warmup=2)
    slow = AdaptiveBand(alpha=0.5, k=3.0, min_std=0.1, warmup=2, alpha_run=0.1)
    for band in (fast, slow):
        band.update(1.0)
        band.update(1.0)  # warmup uses alpha for both
        band.update(2.0)
    assert math.isclose(fast.mean, 1.5)
    assert math.isclose(slow.mean, 1.1)


def test_from_env_reads_the_baseline_protection_options():
    detector = EntropyDetector.from_env(
        {"SDN_ENTROPY_UPDATE_HOLD": "2", "SDN_ENTROPY_ALPHA_RUN": "0.05"}
    )
    assert detector.update_hold == 2
    assert detector.alpha_run == 0.05
    default = EntropyDetector.from_env({})
    assert default.update_hold == 0 and default.alpha_run is None


def test_mean_rates_use_every_poll_in_the_window():
    polls = [
        (5.0, {("a", "v"): 5.0, ("b", "v"): 10.0}),  # 1 pkt/s and 2 pkt/s
        (5.0, {("a", "v"): 15.0}),  # 3 pkt/s, b silent
    ]
    rates = mean_rates(polls)
    assert math.isclose(rates[("a", "v")], 2.0)
    assert math.isclose(rates[("b", "v")], 1.0)
    assert mean_rates([]) == {}
    assert mean_rates([(0.0, {("a", "v"): 3.0})]) == {}


def test_merge_switch_rates_counts_a_flow_once_when_deduplicating():
    per_switch = {
        1: {("a", "v"): 10.0, ("b", "v"): 2.0},
        2: {("a", "v"): 9.0},  # same flow seen at a second switch
    }
    summed = merge_switch_rates(per_switch, dedupe=False)
    assert sorted((f.src, f.weight) for f in summed) == [
        ("a", 9.0),
        ("a", 10.0),
        ("b", 2.0),
    ]
    unique = merge_switch_rates(per_switch, dedupe=True)
    assert sorted((f.src, f.weight) for f in unique) == [("a", 10.0), ("b", 2.0)]


# ---------------------------------------------------------------------------
# Entropy measures, threshold models and the information published per window
# ---------------------------------------------------------------------------


def test_every_measure_agrees_on_a_uniform_distribution():
    uniform = [1, 1, 1, 1]
    assert entropy_of(uniform, "shannon") == 2.0
    assert entropy_of(uniform, "norm") == 1.0
    for order in (0.5, 2.0, 10.0):
        assert math.isclose(entropy_of(uniform, "renyi", order), 2.0)
    assert math.isclose(entropy_of(uniform, "min"), 2.0)
    assert math.isclose(entropy_of(uniform, "tsallis", 2.0), 0.75)


def test_higher_renyi_orders_weigh_the_dominant_value_more():
    skewed = [80, 10, 10]
    values = [entropy_of(skewed, "renyi", order) for order in (0.5, 1.0, 2.0, 10.0)]
    assert values == sorted(values, reverse=True)
    assert math.isclose(values[1], shannon_entropy(skewed))
    assert entropy_of(skewed, "min") <= values[-1]


def test_tsallis_tends_to_shannon_in_nats_when_the_order_tends_to_one():
    skewed = [80, 10, 10]
    nats = shannon_entropy(skewed) * math.log(2)
    assert math.isclose(entropy_of(skewed, "tsallis", 1.0), nats)
    assert math.isclose(entropy_of(skewed, "tsallis", 1.000001), nats, rel_tol=1e-4)


def test_a_histogram_gives_the_same_entropy_as_the_expanded_list():
    expanded = [0.2] * 50 + [30.0]
    for measure, order in (
        ("shannon", 2.0),
        ("renyi", 3.0),
        ("norm", 2.0),
        ("min", 2.0),
    ):
        assert math.isclose(
            entropy_of(expanded, measure, order),
            entropy_of([0.2, 30.0], measure, order, counts=[50, 1]),
        )


def test_unknown_measures_are_rejected_and_nothing_has_zero_entropy():
    with pytest.raises(ValueError):
        entropy_of([1, 1], "nope")
    assert entropy_of([], "renyi") == 0.0
    assert entropy_of([0, 0], "tsallis") == 0.0


def test_the_panel_lists_the_usual_entropies_side_by_side():
    panel = entropy_panel([1, 1, 1, 1])
    assert set(panel) == {
        "shannon",
        "norm",
        "renyi2",
        "renyi10",
        "tsallis2",
        "min",
        "distinct",
    }
    assert panel["shannon"] == 2.0 and panel["norm"] == 1.0 and panel["distinct"] == 4.0


def test_a_median_band_resists_outliers_that_drag_the_mean():
    median = RollingBand(3.0, 0.01, 5, center="median", spread="mad")
    mean = RollingBand(3.0, 0.01, 5, center="mean", spread="std")
    for value in [2.0, 2.02, 1.98, 2.01, 1.99] * 4 + [0.2] * 6:
        median.update(value)
        mean.update(value)
    assert abs(median.center - 2.0) < 0.05
    assert abs(mean.center - 2.0) > 0.3
    assert median.spread < 0.1 < mean.spread


def test_the_history_limits_how_far_back_a_band_remembers():
    band = RollingBand(2.0, 0.0, 1, center="mean", spread="std", history=3)
    for value in (10, 10, 10, 1, 1, 1):
        band.update(value)
    assert band.center == 1.0 and band.spread == 0.0
    whole = RollingBand(2.0, 0.0, 1, center="mean", spread="std")
    for value in (10, 10, 10, 1, 1, 1):
        whole.update(value)
    assert whole.center == 5.5


def test_a_rolling_band_is_ready_after_its_warmup():
    band = RollingBand(3.0, 0.05, 3)
    assert not band.ready
    for value in (1.0, 1.0, 1.0):
        band.update(value)
    assert band.ready and band.lower < 1.0 < band.upper


def test_the_improved_ewma_follows_the_entropy_and_widens_with_noise():
    steady = YuBand(3.0, 0.01, 5)
    for _ in range(10):
        steady.update(2.0)
    assert steady.ready and math.isclose(steady.center, 2.0)
    assert steady.spread == 0.01
    noisy = YuBand(3.0, 0.01, 5)
    for value in (2.0, 2.5, 1.5, 2.4, 1.6, 2.3, 1.7, 2.2, 1.8, 2.1):
        noisy.update(value)
    assert noisy.spread > steady.spread
    assert 1.5 <= noisy.center <= 2.5


@pytest.mark.parametrize(
    ("measure", "order"),
    [
        ("shannon", 2.0),
        ("norm", 2.0),
        ("renyi", 2.0),
        ("renyi", 10.0),
        ("tsallis", 2.0),
        ("min", 2.0),
    ],
)
def test_every_measure_flags_a_flood(measure, order):
    detector = warmed_detector(measure=measure, order=order)
    result = detector.observe(1, flood_window())
    assert result.suspicious
    assert result.measure == measure


def test_the_median_learning_every_window_keeps_alarming_through_a_long_flood():
    detector = EntropyDetector(
        warmup_windows=5, center="median", spread="mad", context="all"
    )
    for _ in range(20):
        detector.observe(1, normal_window())
    floods = [detector.observe(1, flood_window()) for _ in range(6)]
    assert all(result.suspicious for result in floods)
    assert floods[-1].confirmed


def test_an_ewma_learning_every_window_ends_up_accepting_the_flood():
    detector = EntropyDetector(warmup_windows=5, context="all")
    for _ in range(5):
        detector.observe(1, normal_window())
    flags = [detector.observe(1, flood_window()).suspicious for _ in range(40)]
    assert flags[0] and not flags[-1]


def test_a_longer_flood_than_half_the_history_moves_the_median_too():
    detector = EntropyDetector(
        warmup_windows=5, center="median", spread="mad", context="all", history=10
    )
    for _ in range(10):
        detector.observe(1, normal_window())
    flags = [detector.observe(1, flood_window()).suspicious for _ in range(20)]
    assert flags[0] and not flags[-1]


def test_destination_port_entropy_is_watched_when_asked():
    detector = EntropyDetector(
        warmup_windows=5, features=("src", "dst", "dport"), min_total_rate=1.0
    )
    quiet = {"dport": [(30.0, 2), (28.0, 1)]}
    for _ in range(5):
        assert detector.observe(1, normal_window(), quiet).reason == "warmup"
    # a SYN flood: every reply is a flow to another ephemeral port, all with a tiny rate
    storm = {"dport": [(0.2, 4000), (900.0, 1)]}
    result = detector.observe(1, normal_window(), storm)
    assert result.suspicious
    assert result.signals["dport"]["out"] is True
    assert result.signals["src"]["out"] is False


def test_a_watched_feature_without_data_is_skipped_for_that_window():
    detector = EntropyDetector(warmup_windows=2, features=("src", "dst", "dport"))
    for _ in range(2):
        detector.observe(1, normal_window())
    result = detector.observe(1, normal_window())
    assert result.evaluated and "dport" not in result.signals


def test_a_nonsensical_configuration_is_rejected():
    for bad in (
        {"measure": "nope"},
        {"center": "nope"},
        {"spread": "nope"},
        {"context": "nope"},
        {"order": 0.0},
        {"features": ("src",)},
        {"features": ("src", "dst", "tcp")},
    ):
        with pytest.raises(ValueError):
            EntropyDetector(**bad)


def test_the_floor_of_the_spread_scales_with_the_measure():
    assert EntropyDetector(measure="shannon", min_std=0.05)._floor() == 0.05
    assert math.isclose(EntropyDetector(measure="norm", min_std=0.05)._floor(), 0.01)
    assert math.isclose(EntropyDetector(measure="tsallis", min_std=0.05)._floor(), 0.01)


def test_from_env_reads_the_measure_and_threshold_options():
    detector = EntropyDetector.from_env(
        {
            "SDN_ENTROPY_MEASURE": "Renyi",
            "SDN_ENTROPY_ORDER": "10",
            "SDN_ENTROPY_CENTER": "median",
            "SDN_ENTROPY_SPREAD": "mad",
            "SDN_ENTROPY_HISTORY": "40",
            "SDN_ENTROPY_CONTEXT": "all",
            "SDN_ENTROPY_FEATURES": "src, dst ,dport",
        }
    )
    assert (detector.measure, detector.order) == ("renyi", 10.0)
    assert (detector.center, detector.spread, detector.history) == ("median", "mad", 40)
    assert detector.context == "all"
    assert detector.features == ("src", "dst", "dport")


def test_results_carry_the_signals_the_panel_and_the_busiest_talkers():
    detector = warmed_detector()
    result = detector.observe(1, flood_window())
    source = result.signals["src"]
    assert set(source) == {"value", "lower", "upper", "center", "spread", "out"}
    assert source["out"] is True
    assert result.h_src is not None
    assert math.isclose(result.panel["src"]["shannon"], result.h_src)
    assert result.top_src[0][0] == "10.0.1.1" and result.top_dst[0][0] == "10.0.1.3"
    details = result.as_details()
    assert details["measure"] == "shannon" and details["center_kind"] == "ewma"
    assert details["signals"] == result.signals
    assert details["top_src"][0][0] == "10.0.1.1"


def test_the_state_of_each_window_is_named():
    detector = EntropyDetector(warmup_windows=5)
    assert window_state(detector.observe(1, normal_window())) == "warmup"
    for _ in range(4):
        detector.observe(1, normal_window())
    assert window_state(detector.observe(1, normal_window())) == "normal"
    idle = detector.observe(1, [FlowObservation("a", "b", 1.0)])
    assert window_state(idle) == "idle"
    assert (
        idle.signals["src"]["value"] is None
        and idle.signals["src"]["lower"] is not None
    )
    assert window_state(detector.observe(1, flood_window())) == "suspicious"
    assert window_state(detector.observe(1, flood_window())) == "alarm"


def test_a_signal_is_formatted_for_a_log_line():
    signal = {"value": 2.31, "lower": 1.9, "upper": 3.4, "center": 2.65, "out": True}
    assert format_signal("src", signal) == "src=2.310[1.90..3.40 c=2.65]!"
    assert format_signal("dst", {"value": None}) == "dst=-"
    assert format_signal("dst", {"value": 1.0, "lower": None}) == "dst=1.000"
