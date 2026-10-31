"""Fail-closed preflight checks; no optional backend or native import required."""
import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest


spec = importlib.util.spec_from_file_location(
    "pq_wrapper_probe", Path(__file__).parent / "pq_vectors/check_wrapper.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def test_missing_library_stops_before_wrapper_lookup(tmp_path, monkeypatch):
    metadata = Mock(side_effect=AssertionError("Metadata must not be consulted"))
    monkeypatch.setattr(probe.importlib.metadata, "version", metadata)
    with pytest.raises(FileNotFoundError):
        probe.check(tmp_path / "missing", "unused")
    metadata.assert_not_called()


@pytest.mark.parametrize("version", [None, "0.16.0.2"])
def test_missing_or_mismatched_wrapper_stops_before_native_load(monkeypatch, version):
    def metadata(name):
        if version is None:
            raise probe.importlib.metadata.PackageNotFoundError(name)
        return version
    monkeypatch.setattr(probe.importlib.metadata, "version", metadata)
    loader = Mock(side_effect=AssertionError("Native must not load"))
    monkeypatch.setattr(probe.ctypes, "CDLL", loader)
    with pytest.raises((RuntimeError, probe.importlib.metadata.PackageNotFoundError)):
        probe.check(__file__, "unused")
    loader.assert_not_called()


def test_mismatched_native_stops_before_wrapper_import(monkeypatch):
    monkeypatch.setattr(probe.importlib.metadata, "version", lambda _: "0.14.0")
    native = Mock()
    native.OQS_version.return_value = b"0.16.0"
    monkeypatch.setattr(probe.ctypes, "CDLL", lambda _: native)
    hook = Mock(side_effect=AssertionError("Must stop before import guard"))
    monkeypatch.setattr(probe.sys, "addaudithook", hook)
    with pytest.raises(RuntimeError, match="Expected native"):
        probe.check(__file__, "unused")
    hook.assert_not_called()
