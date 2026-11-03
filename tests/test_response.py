import ipaddress
from typing import Any, List, Tuple

import pytest

from sdn_ddos.controller.enforcer import (
    DROP_PRIORITY,
    LIMIT_PRIORITY,
    OpenFlowEnforcer,
)
from sdn_ddos.controller.response import (
    DROP,
    LIMIT,
    ResponseManager,
    ResponseSettings,
)

LAB = (ipaddress.IPv4Network("10.0.0.0/8"),)


class FakeEnforcer:
    def __init__(self, switches: int = 4) -> None:
        self.switches = switches
        self.calls: List[Tuple[str, str]] = []

    def drop(self, source: str, seconds: int) -> int:
        self.calls.append(("drop", source))
        return self.switches

    def limit(self, source: str, pps: int, burst: int, seconds: int) -> int:
        self.calls.append(("limit", source))
        return self.switches

    def release(self, source: str) -> None:
        self.calls.append(("release", source))


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def manager(
    policy: str = "block", enforcer: Any = None, clock: Any = None, **overrides: Any
) -> ResponseManager:
    settings = ResponseSettings(
        policy=policy, block_seconds=300, limit_seconds=60, **overrides
    )
    return ResponseManager(settings, LAB, enforcer or FakeEnforcer(), clock or Clock())


def test_block_policy_drops_once_per_source() -> None:
    enforcer = FakeEnforcer()
    responder = manager("block", enforcer)
    action = responder.respond("10.0.0.1", reason="llm")
    assert action is not None and action.kind == DROP and action.switches == 4
    assert action.label == "temporary_drop" and action.seconds == 300
    assert responder.respond("10.0.0.1") is None
    assert enforcer.calls == [("drop", "10.0.0.1")]


def test_rate_limit_policy_never_blocks_and_labels_the_rate() -> None:
    enforcer = FakeEnforcer()
    responder = manager("rate_limit", enforcer, limit_pps=25, limit_burst=50)
    action = responder.respond("10.0.0.1")
    assert action is not None and action.kind == LIMIT and action.pps == 25
    assert action.label == "rate_limit_25pps" and action.seconds == 60
    assert responder.respond("10.0.0.1") is None
    assert [call[0] for call in enforcer.calls] == ["limit"]


def test_escalate_limits_first_then_blocks_after_the_grace_period() -> None:
    enforcer, clock = FakeEnforcer(), Clock()
    responder = manager("escalate", enforcer, clock, escalate_after=20)
    first = responder.respond("10.0.0.1")
    assert first is not None and first.kind == LIMIT
    clock.now += 10
    assert responder.respond("10.0.0.1") is None  # too soon to escalate
    clock.now += 11
    second = responder.respond("10.0.0.1")
    assert second is not None and second.kind == DROP
    assert enforcer.calls == [
        ("limit", "10.0.0.1"),
        ("drop", "10.0.0.1"),
        ("release", "10.0.0.1"),
    ]
    assert responder.respond("10.0.0.1") is None  # already blocked
    assert responder.active() == {"10.0.0.1": DROP}


def test_actions_expire_and_free_the_meter() -> None:
    enforcer, clock = FakeEnforcer(), Clock()
    responder = manager("rate_limit", enforcer, clock)
    responder.respond("10.0.0.1")
    clock.now += 61
    assert responder.expire() == ["10.0.0.1"]
    assert enforcer.calls[-1] == ("release", "10.0.0.1")
    again = responder.respond("10.0.0.1")
    assert again is not None and again.kind == LIMIT


def test_rejects_unsafe_or_unusable_sources() -> None:
    enforcer = FakeEnforcer()
    responder = manager(
        "block", enforcer, protected=(ipaddress.IPv4Network("10.0.0.2/32"),)
    )
    for source in (None, "", "not-an-ip", "8.8.8.8", "::1", "10.0.0.2"):
        assert responder.respond(source) is None
    assert enforcer.calls == []


def test_dry_run_records_without_touching_switches() -> None:
    enforcer = FakeEnforcer()
    responder = manager("escalate", enforcer, dry_run=True)
    action = responder.respond("10.0.0.1")
    assert action is not None and action.dry_run and action.switches == 0
    assert action.label == "dry_run_rate_limit_50pps"
    assert responder.respond("10.0.0.1") is None
    assert enforcer.calls == []


def test_not_remembered_when_no_switch_took_the_action() -> None:
    enforcer = FakeEnforcer(switches=0)
    responder = manager("block", enforcer)
    assert responder.respond("10.0.0.1") is None
    enforcer.switches = 2
    assert responder.respond("10.0.0.1") is not None


def test_max_active_caps_the_number_of_handled_sources() -> None:
    responder = manager("block", max_active=2)
    assert responder.respond("10.0.0.1") is not None
    assert responder.respond("10.0.0.2") is not None
    assert responder.respond("10.0.0.3") is None


def test_settings_from_env_and_validation() -> None:
    settings = ResponseSettings.from_env(
        {
            "SDN_RESPONSE_POLICY": "Escalate",
            "SDN_RATE_LIMIT_PPS": "80",
            "SDN_RESPONSE_PROTECTED": "10.0.0.2, 10.9.0.0/24",
            "SDN_RESPONSE_DRY_RUN": "yes",
        },
        block_seconds=120,
    )
    assert settings.policy == "escalate" and settings.limit_burst == 160
    assert settings.dry_run and settings.block_seconds == 120
    assert len(settings.protected) == 2
    for bad in ({"SDN_RESPONSE_POLICY": "nuke"}, {"SDN_RATE_LIMIT_PPS": "0"}):
        with pytest.raises(ValueError):
            ResponseSettings.from_env(bad)


class Msg:
    def __init__(self, kind: str, **fields: Any) -> None:
        self.kind, self.fields = kind, fields


class FakeParser:
    def OFPMatch(self, **fields: Any) -> Msg:
        return Msg("match", **fields)

    def OFPFlowMod(self, **fields: Any) -> Msg:
        return Msg("flow", **fields)

    def OFPMeterMod(self, **fields: Any) -> Msg:
        return Msg("meter", **fields)

    def OFPMeterBandDrop(self, **fields: Any) -> Msg:
        return Msg("band", **fields)

    def OFPInstructionMeter(self, meter_id: int) -> Msg:
        return Msg("instr_meter", meter_id=meter_id)

    def OFPInstructionActions(self, kind: int, actions: List[Any]) -> Msg:
        return Msg("instr_actions", actions=actions)

    def OFPActionOutput(self, port: int) -> Msg:
        return Msg("output", port=port)


class FakeProto:
    OFPIT_APPLY_ACTIONS = 4
    OFPMC_ADD, OFPMC_DELETE = 0, 2
    OFPMF_PKTPS, OFPMF_BURST = 2, 4
    OFPP_NORMAL = 0xFFFFFFFA


class FakeDatapath:
    ofproto = FakeProto()
    ofproto_parser = FakeParser()

    def __init__(self) -> None:
        self.sent: List[Msg] = []

    def send_msg(self, message: Msg) -> None:
        self.sent.append(message)


def test_enforcer_drop_installs_an_empty_action_rule_on_every_switch() -> None:
    switches = {1: FakeDatapath(), 2: FakeDatapath()}
    assert OpenFlowEnforcer(switches).drop("10.0.0.1", 300) == 2
    flow = switches[1].sent[0]
    assert flow.kind == "flow" and flow.fields["priority"] == DROP_PRIORITY
    assert flow.fields["hard_timeout"] == 300
    assert flow.fields["match"].fields == {"eth_type": 0x0800, "ipv4_src": "10.0.0.1"}
    assert flow.fields["instructions"][0].fields["actions"] == []


def test_enforcer_limit_adds_a_meter_then_a_rule_that_uses_it() -> None:
    switches = {1: FakeDatapath()}
    enforcer = OpenFlowEnforcer(switches)
    assert enforcer.limit("10.0.0.1", 50, 100, 120) == 1
    meter, flow = switches[1].sent
    assert meter.kind == "meter" and meter.fields["meter_id"] == 1
    assert meter.fields["flags"] == 6 and meter.fields["command"] == 0
    band = meter.fields["bands"][0].fields
    assert band == {"rate": 50, "burst_size": 100}
    assert flow.fields["priority"] == LIMIT_PRIORITY < DROP_PRIORITY
    instructions = flow.fields["instructions"]
    assert instructions[0].fields["meter_id"] == 1
    assert instructions[1].fields["actions"][0].fields["port"] == FakeProto.OFPP_NORMAL


def test_enforcer_gives_each_source_its_own_meter_and_release_deletes_it() -> None:
    switches = {1: FakeDatapath()}
    enforcer = OpenFlowEnforcer(switches)
    enforcer.limit("10.0.0.1", 50, 100, 60)
    enforcer.limit("10.0.0.2", 50, 100, 60)
    ids = [m.fields["meter_id"] for m in switches[1].sent if m.kind == "meter"]
    assert ids == [1, 2]
    enforcer.release("10.0.0.1")
    deleted = switches[1].sent[-1]
    assert deleted.fields["command"] == 2 and deleted.fields["meter_id"] == 1
    enforcer.release("10.0.0.1")  # unknown source: nothing more is sent
    assert switches[1].sent[-1] is deleted
    enforcer.limit("10.0.0.3", 50, 100, 60)  # reuses the freed id
    assert switches[1].sent[-2].fields["meter_id"] == 1


def test_enforcer_without_switches_reports_zero() -> None:
    enforcer = OpenFlowEnforcer({})
    assert enforcer.limit("10.0.0.1", 50, 100, 60) == 0
    assert enforcer.drop("10.0.0.1", 60) == 0


def test_review_escalates_a_limited_source_that_keeps_exceeding_the_cap() -> None:
    enforcer, clock = FakeEnforcer(), Clock()
    responder = manager("escalate", enforcer, clock, escalate_after=20, limit_pps=50)
    responder.respond("10.0.0.1")  # limited
    assert responder.review({"10.0.0.1": 900.0}) == []  # starts counting
    clock.now += 10
    assert responder.review({"10.0.0.1": 800.0}) == []  # not long enough
    clock.now += 11
    actions = responder.review({"10.0.0.1": 850.0})
    assert [a.kind for a in actions] == [DROP] and actions[0].reason == "exceeds_limit"
    assert enforcer.calls[-2:] == [("drop", "10.0.0.1"), ("release", "10.0.0.1")]
    assert responder.active() == {"10.0.0.1": DROP}
    assert responder.review({"10.0.0.1": 900.0}) == []  # already blocked


def test_review_resets_when_the_source_complies_and_ignores_other_policies() -> None:
    enforcer, clock = FakeEnforcer(), Clock()
    responder = manager("escalate", enforcer, clock, escalate_after=20, limit_pps=50)
    responder.respond("10.0.0.1")
    responder.review({"10.0.0.1": 900.0})
    clock.now += 15
    assert responder.review({"10.0.0.1": 40.0}) == []  # back under 2x the cap
    clock.now += 15
    assert responder.review({"10.0.0.1": 900.0}) == []  # the clock restarted
    assert responder.review({"unknown": 900.0}) == []  # not a limited source

    for policy in ("rate_limit", "block"):
        other = manager(policy, FakeEnforcer(), Clock())
        other.respond("10.0.0.1")
        other.clock.now += 100  # type: ignore[attr-defined]
        assert other.review({"10.0.0.1": 5000.0}) == []


def test_review_never_touches_dry_run_sources() -> None:
    enforcer, clock = FakeEnforcer(), Clock()
    responder = manager("escalate", enforcer, clock, dry_run=True, escalate_after=1)
    responder.respond("10.0.0.1")
    responder.review({"10.0.0.1": 900.0})
    clock.now += 5
    assert responder.review({"10.0.0.1": 900.0}) == []
    assert enforcer.calls == []


def test_confirmation_ignores_one_off_detections_and_acts_on_persistent_ones() -> None:
    clock = Clock()
    enforcer = FakeEnforcer()
    responder = manager("block", enforcer, clock, confirm_hits=2, confirm_seconds=30)
    # A false alarm: flagged once, never again. Nothing happens, however long we wait.
    assert responder.respond("10.0.0.9") is None
    clock.now += 60
    assert responder.respond("10.0.0.2") is None  # a different source starts counting
    assert enforcer.calls == []
    # A flood: flagged by several switches in the same poll (one hit), then next poll.
    assert responder.respond("10.0.0.1") is None
    clock.now += 0.5
    assert responder.respond("10.0.0.1") is None  # same poll seen by another switch
    clock.now += 5
    action = responder.respond("10.0.0.1")
    assert action is not None and action.kind == DROP
    assert enforcer.calls == [("drop", "10.0.0.1")]


def test_confirmation_uses_when_the_poll_was_read_not_when_it_was_judged() -> None:
    clock = Clock()
    enforcer = FakeEnforcer()
    responder = manager("block", enforcer, clock, confirm_hits=2, confirm_gap=1.0)
    base = clock.now
    # One poll seen by two switches; a slow model judges them 4 s apart, but they carry
    # the same observation time, so they are one hit.
    assert responder.respond("10.0.0.1", detected_at=base) is None
    clock.now += 4
    assert responder.respond("10.0.0.1", detected_at=base + 0.2) is None
    # The next poll, 2 s later (fast polling), is a second hit.
    clock.now += 1
    action = responder.respond("10.0.0.1", detected_at=base + 2.0)
    assert action is not None and action.kind == DROP


def test_confirmation_hits_expire_and_do_not_apply_to_escalation() -> None:
    clock = Clock()
    enforcer = FakeEnforcer()
    responder = manager(
        "escalate",
        enforcer,
        clock,
        confirm_hits=2,
        confirm_seconds=10,
        escalate_after=20,
    )
    assert responder.respond("10.0.0.1") is None
    clock.now += 15  # the first hit is too old to count with the second
    assert responder.respond("10.0.0.1") is None
    clock.now += 5
    first = responder.respond("10.0.0.1")
    assert first is not None and first.kind == LIMIT
    # Once it is being handled, escalating needs no new confirmation.
    clock.now += 25
    second = responder.respond("10.0.0.1")
    assert second is not None and second.kind == DROP


def test_confirmation_settings_are_validated() -> None:
    with pytest.raises(ValueError, match="confirmation"):
        ResponseSettings(confirm_hits=0)
    with pytest.raises(ValueError, match="confirmation"):
        ResponseSettings(confirm_seconds=0)
    parsed = ResponseSettings.from_env(
        {"SDN_RESPONSE_CONFIRM_HITS": "3", "SDN_RESPONSE_CONFIRM_SECONDS": "45"}
    )
    assert (parsed.confirm_hits, parsed.confirm_seconds) == (3, 45)
    assert parsed.confirm_gap == 2.5  # half of the default 5 s poll
    fast = ResponseSettings.from_env({"SDN_POLL_INTERVAL": "2"})
    assert fast.confirm_gap == 1.0
    with pytest.raises(ValueError, match="gap"):
        ResponseSettings(confirm_gap=0)
