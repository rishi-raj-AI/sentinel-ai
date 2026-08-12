from app.brain.planner import plan_command
from app.tools.evtx import SAMPLE_EVTX_SIZE, create_sample_evtx


def test_sample_evtx_planner_command():
    plan = plan_command("create sample evtx workspace/sample.evtx")
    assert plan.steps[0].tool == "forensic.create_sample_evtx"
    assert plan.steps[0].arguments == {"path": "workspace/sample.evtx"}


def test_sample_evtx_download_validation(tmp_path, monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"ElfFile" + (b"\x00" * (SAMPLE_EVTX_SIZE - 7))

    monkeypatch.setattr("app.tools.evtx.urllib.request.urlopen", lambda *args, **kwargs: Response())
    target = tmp_path / "sample.evtx"
    result = create_sample_evtx(str(target))
    assert result["evtx_signature_valid"] is True
    assert result["bytes_written"] == SAMPLE_EVTX_SIZE
    assert target.read_bytes()[:7] == b"ElfFile"
