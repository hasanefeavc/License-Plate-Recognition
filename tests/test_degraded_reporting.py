"""What the API says when the pipeline is not there.

The degraded-mode contract has always been that a missing model keeps the
service up. What it did not do was say *which* model: ``/health`` reported
"degraded", ``/api/stats`` returned a 503 reading "Görüntü işleme hattı
kullanılamıyor", and both were equally true whether torch was missing, the
weights were absent or a camera was unplugged. On a fresh clone -- the case
that produces this most often -- the answer is one filename.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr.api import deps  # noqa: E402
from lpr.api.main import create_app  # noqa: E402
from lpr.api.security import create_token  # noqa: E402
from lpr.model_assets import describe_assets, resolve_detection_weights  # noqa: E402


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class _FakeUserRepository:
    """Just enough for ``/health``'s ``setup_required`` probe."""

    def is_first_user(self) -> bool:
        return False


@pytest.fixture()
def degraded_app(tmp_settings: Any) -> Any:
    """An app whose pipeline failed to build, exactly as a fresh clone's does."""
    app = create_app(tmp_settings)
    app.state.pipeline = None
    app.state.pipeline_error = "Detection weights not found"
    app.state.model_assets = describe_assets(tmp_settings)
    app.dependency_overrides[deps.get_user_repository] = _FakeUserRepository
    return app


@pytest.fixture()
def degraded_client(degraded_app: Any) -> TestClient:
    # No `with`: the real lifespan must not run.
    return TestClient(degraded_app)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


def test_health_still_answers_200_when_the_pipeline_never_started(
    degraded_client: TestClient,
) -> None:
    """The Docker HEALTHCHECK hits this; a degraded-but-serving API must not be
    restarted in a loop."""
    response = degraded_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"


def test_health_names_the_missing_weights_file(
    degraded_client: TestClient, tmp_settings: Any
) -> None:
    detail = degraded_client.get("/health").json()["detail"]
    assert str(resolve_detection_weights(tmp_settings)) in detail, detail


def test_health_repeats_the_recorded_startup_error(degraded_client: TestClient) -> None:
    assert "Detection weights not found" in degraded_client.get("/health").json()["detail"]


class _NoCamerasPipeline:
    """A pipeline that came up but has no camera connected."""

    running = True

    def stats(self) -> Any:
        return types.SimpleNamespace(started_at=0.0, cameras=[])


def test_health_names_a_camera_role_the_configuration_refused(
    tmp_settings: Any,
) -> None:
    """A disabled role looks like an unplugged camera from a health probe.

    It is not, and the difference is the difference between checking a cable
    and editing one line of .env -- so the probe says which it is. This is the
    *running* pipeline path: the process is fine, the cameras are not.
    """
    from lpr.config import CameraConfig, CamerasConfig

    tmp_settings.cameras = CamerasConfig(
        entry=CameraConfig(source="0"), exit=CameraConfig(source="0")
    )
    app = create_app(tmp_settings)
    app.state.pipeline = _NoCamerasPipeline()
    app.dependency_overrides[deps.get_user_repository] = _FakeUserRepository

    body = TestClient(app).get("/health").json()
    assert body["status"] == "degraded"
    assert "exit" in body["detail"] and "entry" in body["detail"], body["detail"]


def test_health_falls_back_to_the_generic_camera_message(tmp_settings: Any) -> None:
    """With a sound configuration, no camera really does mean no camera."""
    from lpr.config import CameraConfig, CamerasConfig

    tmp_settings.cameras = CamerasConfig(
        entry=CameraConfig(source="0"), exit=CameraConfig(source="1")
    )
    app = create_app(tmp_settings)
    app.state.pipeline = _NoCamerasPipeline()
    app.dependency_overrides[deps.get_user_repository] = _FakeUserRepository

    assert TestClient(app).get("/health").json()["detail"] == "Kamera bağlantısı yok"


# ---------------------------------------------------------------------------
# The 503
# ---------------------------------------------------------------------------


def test_the_stats_503_names_what_is_missing(degraded_client: TestClient) -> None:
    """The reported symptom: an unexplained 503 from /api/stats on a fresh
    checkout."""
    response = degraded_client.get("/api/stats", headers=auth(create_token("a", "admin")))
    assert response.status_code == 503
    detail = response.json()["error"]["detail"]
    assert "Detection weights not found" in detail
    assert "plate_yolov8n" in detail, detail


def test_the_503_still_carries_the_original_message(degraded_client: TestClient) -> None:
    """Clients switch on the Turkish phrase; it stays at the front."""
    response = degraded_client.get("/api/stats", headers=auth(create_token("a", "admin")))
    assert response.json()["error"]["detail"].startswith(
        "Görüntü işleme hattı kullanılamıyor"
    )


# ---------------------------------------------------------------------------
# /api/system/assets
# ---------------------------------------------------------------------------


def test_the_assets_endpoint_reports_the_missing_model(
    degraded_client: TestClient, tmp_settings: Any
) -> None:
    response = degraded_client.get(
        "/api/system/assets", headers=auth(create_token("a", "admin"))
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is False
    assert body["detection_present"] is False
    assert body["detection_weights"] == str(resolve_detection_weights(tmp_settings))
    assert body["missing"], "something must be named as missing"


def test_the_assets_endpoint_requires_authentication(degraded_client: TestClient) -> None:
    assert degraded_client.get("/api/system/assets").status_code == 401


def test_the_assets_endpoint_lists_refused_camera_roles(
    tmp_settings: Any,
) -> None:
    """Both halves of "what did this installation refuse to start, and why?"
    are answered in one place."""
    from lpr.config import CameraConfig, CamerasConfig

    tmp_settings.cameras = CamerasConfig(
        entry=CameraConfig(source="0"), exit=CameraConfig(source="/dev/video0")
    )
    app = create_app(tmp_settings)
    app.state.pipeline = None
    client = TestClient(app)

    body = client.get(
        "/api/system/assets", headers=auth(create_token("a", "admin"))
    ).json()
    assert [issue["role"] for issue in body["cameras"]] == ["exit"]
    assert body["cameras"][0]["reason"] == "duplicate"


def test_the_assets_endpoint_answers_without_the_ml_stack(
    degraded_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The box where torch is what is missing is the box where somebody asks."""
    import builtins

    real_import = builtins.__import__

    def refuse_ml(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.split(".")[0] in {"torch", "ultralytics", "easyocr"}:
            raise ImportError(f"{name} is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse_ml)
    response = degraded_client.get(
        "/api/system/assets", headers=auth(create_token("a", "admin"))
    )
    assert response.status_code == 200
