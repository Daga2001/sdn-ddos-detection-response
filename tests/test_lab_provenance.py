from pathlib import Path

from sdn_ddos.lab.contracts import DetectionConfig, EntropyParams, Experiment
from sdn_ddos.lab.provenance import (
    os_release,
    package_version,
    repository_commit,
    settings_fingerprint,
)


def test_the_fingerprint_follows_the_detector_settings_not_the_attack():
    base = DetectionConfig(mode="llm", prompt="lab")
    same = DetectionConfig(mode="llm", prompt="lab")
    assert settings_fingerprint(base, "port_free") == settings_fingerprint(
        same, "port_free"
    )
    assert len(settings_fingerprint(base, "port_free")) == 16
    changed = [
        settings_fingerprint(DetectionConfig(mode="llm", prompt="insdn"), "port_free"),
        settings_fingerprint(DetectionConfig(mode="llm", threshold=0.5), "port_free"),
        settings_fingerprint(base, "per_port"),
        settings_fingerprint(
            DetectionConfig(mode="entropy", entropy=EntropyParams(k=3)), "port_free"
        ),
        settings_fingerprint(None, "port_free"),
    ]
    assert len(set(changed)) == len(changed)
    assert settings_fingerprint(base, "port_free") not in changed


def test_purpose_and_test_case_default_safely_and_are_validated():
    run = Experiment(attackers=["h1"], victims=["h2"])
    assert run.purpose == "exploration" and run.scenario == ""
    held = Experiment(
        attackers=["h1"], victims=["h2"], purpose="held_out", scenario="TC-2"
    )
    assert held.purpose == "held_out" and held.scenario == "TC-2"
    for bad in ({"purpose": "final"}, {"scenario": "TC 2; rm"}, {"scenario": "x" * 41}):
        try:
            Experiment(attackers=["h1"], victims=["h2"], **bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad} was accepted")


def test_the_commit_is_read_from_the_environment_or_a_mounted_git_dir(tmp_path: Path):
    assert repository_commit(
        {"SDN_GIT_COMMIT": "abc123", "SDN_GIT_BRANCH": "main"}
    ) == {
        "commit": "abc123",
        "branch": "main",
    }
    git = tmp_path / "git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/feat/x\n")
    (git / "refs" / "heads" / "feat").mkdir()
    (git / "refs" / "heads" / "feat" / "x").write_text("1111\n")
    assert repository_commit({"SDN_GIT_DIR": str(git)}) == {
        "commit": "1111",
        "branch": "feat/x",
    }
    (git / "refs" / "heads" / "feat" / "x").unlink()
    (git / "packed-refs").write_text("# pack-refs\n2222 refs/heads/feat/x\n")
    assert repository_commit({"SDN_GIT_DIR": str(git)})["commit"] == "2222"
    (git / "HEAD").write_text("3333\n")
    assert repository_commit({"SDN_GIT_DIR": str(git)}) == {
        "commit": "3333",
        "branch": "",
    }
    missing = repository_commit({"SDN_GIT_DIR": str(tmp_path / "none")})
    assert missing == {"commit": "unknown", "branch": ""}


def test_os_release_and_package_versions_never_fail(tmp_path: Path):
    release = tmp_path / "os-release"
    release.write_text('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 22.04.5 LTS"\n')
    assert os_release(str(release)) == "Ubuntu 22.04.5 LTS"
    assert os_release(str(tmp_path / "missing")) == "unknown"
    release.write_text("NAME=x\n")
    assert os_release(str(release)) == "unknown"
    assert package_version("pydantic") != "not_installed"
    assert package_version("no-such-package-here") == "not_installed"
