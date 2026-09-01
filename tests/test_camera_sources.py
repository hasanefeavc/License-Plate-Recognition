"""Camera source classification and the two configurations that must be refused.

Both failures this covers present identically at runtime -- a capture backend
that will not open, retried forever -- and identically to an unplugged camera,
which is why they survived so long. They are caught in the config layer now,
where the string is still a string and can be reasoned about.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr.config import CameraConfig, CamerasConfig  # noqa: E402

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "kind"),
    [
        ("0", "index"),
        ("1", "index"),
        ("", "disabled"),
        ("   ", "disabled"),
        ("rtsp://10.0.0.5/stream", "url"),
        ("http://cam.local/mjpeg", "url"),
        ("not a camera", "invalid"),
        ("COM3", "invalid"),  # a serial port is not a camera
    ],
)
def test_source_kind(source: str, kind: str) -> None:
    assert CameraConfig(source=source).source_kind == kind


@pytest.mark.parametrize("source", ["0", " 0 ", "00", "+0", "\t0\n"])
def test_a_string_integer_is_a_device_index_however_it_is_spelled(source: str) -> None:
    """Windows configs are typed by hand and pick up whitespace and zeroes.

    All of these are camera 0, and all of them have to reach OpenCV as the
    *int* 0 -- ``VideoCapture(" 0 ")`` is a filename, and it opens nothing.
    """
    config = CameraConfig(source=source)
    assert config.source_kind == "index"
    assert config.resolved_source == 0
    assert config.device_key == "v4l2:0"


def test_a_video_file_is_a_valid_source(tmp_path: Path) -> None:
    """Replaying a recording is how the pipeline is tested without a camera."""
    clip = tmp_path / "gate.mp4"
    clip.write_bytes(b"")
    assert CameraConfig(source=str(clip)).source_kind == "file"


def test_the_two_spellings_of_one_webcam_share_a_device_key() -> None:
    assert CameraConfig(source="0").device_key == CameraConfig(source="/dev/video0").device_key
    assert CameraConfig(source="1").device_key != CameraConfig(source="/dev/video0").device_key


def test_a_url_is_its_own_device_key() -> None:
    assert CameraConfig(source="rtsp://cam/1").device_key == "rtsp://cam/1"


def test_a_disabled_camera_collides_with_nothing() -> None:
    config = CameraConfig(source="")
    assert config.resolved_source is None
    assert config.device_key is None
    assert not config.enabled


def test_a_linux_device_node_is_rewritten_to_an_index_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``/dev/video1`` cannot exist on Windows, but it does name camera 1.

    Refusing it would be defensible and unhelpful: the config was almost
    certainly written on the Linux box and carried over, and the two spellings
    already mean the same device everywhere else in the config layer.
    """
    monkeypatch.setattr("lpr.config.IS_WINDOWS", True)
    config = CameraConfig(source="/dev/video1")
    assert config.normalised_source == "1"
    assert config.resolved_source == 1


def test_a_linux_device_node_is_left_alone_on_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("lpr.config.IS_WINDOWS", False)
    config = CameraConfig(source="/dev/video1")
    assert config.normalised_source == "/dev/video1"
    assert config.resolved_source == "/dev/video1"


def test_a_directshow_device_name_is_recognised_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("lpr.config.IS_WINDOWS", True)
    assert CameraConfig(source="video=Integrated Webcam").source_kind == "device"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_two_roles_on_one_device_disables_the_second() -> None:
    """The reported Windows failure: entry and exit both set to camera 0.

    DirectShow locks the device, so the second VideoCapture takes the capture
    pipeline down with it rather than getting a second stream.
    """
    cameras = CamerasConfig(entry=CameraConfig(source="0"), exit=CameraConfig(source="0"))
    assert cameras.entry.source == "0", "the first role keeps the device"
    assert cameras.exit.source == "", "the second is disabled, not left to fail"
    assert not cameras.exit.enabled

    (issue,) = cameras.issues
    assert issue.role == "exit"
    assert issue.reason == "duplicate"
    assert "entry" in issue.message


def test_the_collision_is_caught_across_spellings() -> None:
    """``entry: "0"`` and ``exit: "/dev/video0"`` are one webcam, not two."""
    cameras = CamerasConfig(entry=CameraConfig(source="0"), exit=CameraConfig(source="/dev/video0"))
    assert cameras.exit.source == ""
    assert [issue.reason for issue in cameras.issues] == ["duplicate"]


def test_an_unopenable_source_disables_only_its_own_role() -> None:
    """A typo on one camera must not cost the site the other one."""
    cameras = CamerasConfig(entry=CameraConfig(source="camera one"), exit=CameraConfig(source="1"))
    assert cameras.entry.source == ""
    assert cameras.exit.source == "1", "the good camera keeps working"
    (issue,) = cameras.issues
    assert issue.role == "entry"
    assert issue.reason == "invalid"
    assert issue.source == "camera one", "the issue records what was configured"


def test_two_different_cameras_are_left_alone() -> None:
    cameras = CamerasConfig(entry=CameraConfig(source="0"), exit=CameraConfig(source="1"))
    assert cameras.issues == []
    assert cameras.entry.enabled and cameras.exit.enabled


def test_two_roles_on_one_rtsp_url_still_collide() -> None:
    """An RTSP server usually *can* serve two readers -- but nobody means to.

    Two roles on one URL means both cameras see the same lane, so entry and
    exit decisions are made from identical frames. That is a configuration
    mistake worth naming, not a capability worth using.
    """
    url = "rtsp://10.0.0.5/stream"
    cameras = CamerasConfig(entry=CameraConfig(source=url), exit=CameraConfig(source=url))
    assert cameras.exit.source == ""
    assert cameras.issues[0].reason == "duplicate"


def test_a_single_camera_site_reports_no_issue() -> None:
    """A blank source is the normal one-camera setup, not a misconfiguration."""
    cameras = CamerasConfig(entry=CameraConfig(source="0"), exit=CameraConfig(source=""))
    assert cameras.issues == []
