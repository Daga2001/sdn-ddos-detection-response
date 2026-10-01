import pytest

from sdn_ddos.config import ConfigurationError
from sdn_ddos.experiments import attack_launcher


def test_hping_command_is_bounded() -> None:
    command = attack_launcher.build_hping_command("10.0.2.1", 80, 100, 20)
    assert "--flood" not in command
    assert command[-2:] == ["2000", "10.0.2.1"]
    assert command[command.index("--interval") + 1] == "u10000"


def test_hping_command_supports_bounded_traffic_kinds() -> None:
    syn = attack_launcher.build_hping_command("10.0.2.1", 80, 100, 20, "syn")
    udp = attack_launcher.build_hping_command("10.0.2.1", 80, 100, 20, "udp")
    icmp = attack_launcher.build_hping_command("10.0.2.1", 80, 100, 20, "icmp")
    assert syn[:2] == ["hping3", "--syn"] and "--destport" in syn
    assert udp[:2] == ["hping3", "--udp"] and "--destport" in udp
    # An ICMP echo flood has no transport port, but the same hard ceiling holds.
    assert icmp[:2] == ["hping3", "--icmp"] and "--destport" not in icmp
    for command in (syn, udp, icmp):
        assert "--flood" not in command
        assert command[-2:] == ["2000", "10.0.2.1"]
    with pytest.raises(ConfigurationError, match="traffic kind"):
        attack_launcher.build_hping_command("10.0.2.1", 80, 100, 20, "fin")


def test_dry_run_validates_without_confirmation(capsys) -> None:
    assert attack_launcher.main(["--target", "10.0.2.1", "--dry-run"]) == 0
    assert "Validated command" in capsys.readouterr().out


def test_launcher_rejects_public_target() -> None:
    with pytest.raises(ConfigurationError, match="outside"):
        attack_launcher.main(["--target", "8.8.8.8", "--dry-run"])


def test_launcher_requires_lab_confirmation() -> None:
    with pytest.raises(ConfigurationError, match="confirm-isolated-lab"):
        attack_launcher.main(["--target", "10.0.2.1"])


def test_launcher_enforces_rate_cap() -> None:
    with pytest.raises(ConfigurationError, match="rate"):
        attack_launcher.main(["--target", "10.0.2.1", "--rate", "1001", "--dry-run"])


def test_successful_run_records_window(monkeypatch) -> None:
    calls = []

    class FakeProcess:
        pid = 999
        returncode = 0

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    class FakeStore:
        def record_attack_window(self, start, end, attack_type, target):
            calls.append((attack_type, target))

        def close(self):
            calls.append(("closed", ""))

    monkeypatch.setattr(
        attack_launcher.shutil, "which", lambda name: "/usr/sbin/hping3"
    )
    monkeypatch.setattr(
        attack_launcher.subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProcess(),
    )
    monkeypatch.setattr(
        attack_launcher,
        "create_metrics_store",
        lambda settings: FakeStore(),
    )
    assert attack_launcher.main(["--target", "10.0.2.1", "--confirm-isolated-lab"]) == 0
    assert calls == [("SYN_RATE", "10.0.2.1"), ("closed", "")]
