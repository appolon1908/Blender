from pathlib import Path
import importlib

from fastapi.testclient import TestClient


def load(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CODESTRA_AUTH_MODE", "development")
    monkeypatch.setenv("CODESTRA_DB_PATH", str(tmp_path / "jobs.sqlite3"))
    monkeypatch.setenv("CODESTRA_INPUT_ROOT", str(tmp_path / "inputs"))
    monkeypatch.setenv("CODESTRA_OUTPUT_ROOT", str(tmp_path / "outputs"))
    import codestra_saas
    return importlib.reload(codestra_saas)


def test_health_ready_and_idempotency(tmp_path, monkeypatch):
    mod = load(tmp_path, monkeypatch); client = TestClient(mod.app)
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    h={"X-Tenant-ID":"t1","X-Actor-ID":"a1","Idempotency-Key":"idem-0001"}
    p={"kind":"render_frame","project_id":"p1","parameters":{"frame":1}}
    one=client.post("/v1/jobs",headers=h,json=p); two=client.post("/v1/jobs",headers=h,json=p)
    assert one.status_code == 202 and one.json()["id"] == two.json()["id"]
    assert client.get(f"/v1/jobs/{one.json()['id']}",headers={"X-Tenant-ID":"other"}).status_code == 404


def test_command_is_bounded_and_render_action_last(tmp_path, monkeypatch):
    mod = load(tmp_path, monkeypatch)
    src=mod.settings.input_root / "scene.blend"; src.parent.mkdir(parents=True,exist_ok=True); src.write_bytes(b"x")
    job={"kind":"render_frame","parameters":{"source_path":"scene.blend","output_path":"frame_#####","format":"PNG","frame":10}}
    cmd=mod.command_for(job)
    assert cmd[-2:] == ["-f","10"]
    bad={"kind":"render_frame","parameters":{"source_path":"../escape.blend","frame":1}}
    try: mod.command_for(bad)
    except ValueError as exc: assert str(exc) == "path_outside_workspace"
    else: raise AssertionError("path traversal accepted")
