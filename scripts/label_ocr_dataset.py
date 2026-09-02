#!/usr/bin/env python3
"""Build an OCR ground-truth file by confirming or correcting what the gate read.

The project can measure OCR accuracy (``lpr.evaluation``) but has had nothing
to measure it *against*: ``datasets/plates`` is a detection set with hashed
filenames, and the only other images on disk are the gate's own snapshots,
whose filenames carry the plate the pipeline itself decided on. Scoring against
those is scoring the pipeline against its own output -- it reports agreement,
not accuracy, and it is biased toward whatever configuration produced them.

This turns those snapshots into real labels with the cheapest possible human
step: the predicted plate is pre-filled, so a correct read costs one keypress
and only the wrong ones cost typing. A few hundred images is roughly twenty
minutes, and it is the input every OCR decision downstream depends on.

Usage::

    python scripts/label_ocr_dataset.py                     # label data/snapshots
    python scripts/label_ocr_dataset.py --show              # also open each image
    python scripts/label_ocr_dataset.py --limit 100 --shuffle
    python scripts/label_ocr_dataset.py --review            # revisit what is labelled

Then measure against it::

    python scripts/evaluate.py --images data/snapshots \\
        --truth data/ocr_ground_truth.json --device cuda

Keys, at the prompt:

    Enter   accept the pre-filled plate
    text    replace it with what the plate actually says
    n       no plate is legible in this image  (a *negative* sample)
    s       skip -- decide later, nothing is written
    b       back, re-do the previous image
    q       save and quit

Every decision is written to disk before the next image is shown, so an
interrupt, a closed terminal or a power cut costs at most the image on screen.
Re-running resumes: images already in the file are not asked about again.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from lpr.ocr.normalize import normalize_plate, strip_noise  # noqa: E402

#: Image suffixes the gate writes, plus the ones a hand-assembled set arrives as.
IMAGE_SUFFIXES = frozenset({".jpg", ".jpeg", ".png", ".bmp", ".webp"})

#: The snapshot naming convention: ``<date>_<time>_<PLATE>.jpg``. The plate is
#: the trailing field, which is why this anchors on the end rather than trying
#: to parse the timestamp.
#:
#: The two leading digits are the province code, and requiring them is what
#: stops an ordinary filename from producing a confident nonsense suggestion --
#: without them ``plain_image.jpg`` offers "IMAGE" as the plate to accept, and
#: one careless Enter puts it in the truth file.
_SNAPSHOT_NAME_RE = re.compile(r"^(?:.*_)?(\d{2}[A-Z0-9]{3,7})$", re.IGNORECASE)

#: Written into the file so a reader knows a blank plate is deliberate.
NEGATIVE = ""


# ---------------------------------------------------------------------------
# Ground-truth file
# ---------------------------------------------------------------------------


@dataclass
class TruthFile:
    """The label set on disk, kept in step with memory after every decision.

    Writes go through a temporary file in the same directory followed by
    ``os.replace``, which is atomic on POSIX and on Windows. The naive
    ``open(path, "w")`` truncates first, so an interrupt during the write
    leaves a half-written file -- and this file is the only copy of work that
    cost a human twenty minutes.
    """

    path: Path
    #: Basename -> plate. Basename because that is the key
    #: :func:`lpr.evaluation.load_ground_truth` builds, so the file survives
    #: the image directory being moved or renamed.
    labels: dict[str, str]
    #: Full relative path per basename, for the record written out.
    sources: dict[str, str]

    @classmethod
    def load(cls, path: Path) -> TruthFile:
        labels: dict[str, str] = {}
        sources: dict[str, str] = {}
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SystemExit(
                    f"{path} exists but could not be read as JSON ({exc}). "
                    "Move it aside if you meant to start over."
                ) from exc
            for record in loaded if isinstance(loaded, list) else []:
                if not isinstance(record, dict):
                    continue
                image = str(record.get("image_path") or record.get("image") or "")
                if not image:
                    continue
                name = Path(image).name
                labels[name] = str(record.get("plate") or "")
                sources[name] = image
        return cls(path=path, labels=labels, sources=sources)

    def record(self, image: Path, plate: str, *, root: Path) -> None:
        """Label one image and persist immediately."""
        name = image.name
        self.labels[name] = plate
        try:
            self.sources[name] = str(image.relative_to(root))
        except ValueError:
            self.sources[name] = str(image)
        self.save()

    def forget(self, image: Path) -> None:
        self.labels.pop(image.name, None)
        self.sources.pop(image.name, None)
        self.save()

    def save(self) -> None:
        """Atomically rewrite the file. Never leaves a partial one behind."""
        payload = [
            {"image_path": self.sources.get(name, name), "plate": plate}
            for name, plate in sorted(self.labels.items())
        ]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            dir=self.path.parent, prefix=f".{self.path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                # fsync before the rename: os.replace only guarantees the
                # directory entry swaps atomically, not that the bytes behind
                # it reached the disk first.
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    @property
    def positives(self) -> int:
        return sum(1 for plate in self.labels.values() if plate)

    @property
    def negatives(self) -> int:
        return sum(1 for plate in self.labels.values() if not plate)


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------


def find_images(root: Path) -> list[Path]:
    """Every image under ``root``, sorted, or the single file it names."""
    if root.is_file():
        return [root]
    if not root.is_dir():
        raise SystemExit(f"{root} does not exist.")
    return sorted(
        path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in IMAGE_SUFFIXES
    )


def _canonical(raw: str) -> str:
    """``raw`` in the form the truth file stores: uppercase, ``A-Z0-9`` only.

    Deliberately *only* formatting -- separators dropped, case folded. It does
    not run :func:`~lpr.ocr.normalize.normalize_plate`, even though that would
    produce the same answer for a well-formed Turkish plate, because that
    function's job is repairing OCR glyph confusions and it will happily bend a
    label into the grammar: a German ``D-AB 1234`` typed by an operator comes
    back as ``04B1234``, a plate that does not exist and that every later
    measurement would then be scored against.

    A human is not an OCR engine. What they typed is the answer; the only thing
    this normalises away is how they chose to punctuate it. Whether it is a
    *Turkish* plate is a separate question, asked by :func:`confirm_odd`.
    """
    return strip_noise(raw.upper())


def predicted_plate(image: Path) -> str:
    """The plate the pipeline wrote into the filename, or ``""``.

    Only a *suggestion*: it is what the gate believed at capture time, which is
    exactly the thing being checked. Returned normalised so accepting it with
    one keypress stores the same canonical form a typed correction would.
    """
    match = _SNAPSHOT_NAME_RE.match(image.stem)
    if not match:
        return ""
    return _canonical(match.group(1))


def open_image(image: Path) -> None:
    """Show the image in whatever the platform uses. Never fatal."""
    opener = (
        ["open"]
        if sys.platform == "darwin"
        else ["cmd", "/c", "start", ""]
        if os.name == "nt"
        else ["xdg-open"]
    )
    if not shutil.which(opener[0]):
        return
    try:
        subprocess.Popen(  # noqa: S603 - fixed opener, path is a local file
            [*opener, str(image)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


# ---------------------------------------------------------------------------
# The prompt
# ---------------------------------------------------------------------------

BANNER = """\
  Enter  accept        n  no plate (negative)      b  back
  text   correct it    s  skip                     q  save and quit
"""


def clean(entry: str) -> str:
    """A typed plate, in the canonical form the truth file stores."""
    return _canonical(entry)


def confirm_odd(plate: str, *, assume_yes: bool) -> bool:
    """Ask before storing a label that is not a valid Turkish plate.

    A typo here is worse than a skipped image: it becomes a permanent wrong
    answer that every later measurement is scored against, and it looks exactly
    like an OCR failure in the report. One keypress is cheap insurance.
    """
    if assume_yes or normalize_plate(plate).is_usable:
        return True
    print(f"  ! {plate!r} is not a valid Turkish plate (province 01-81, 1-3 letters, 2-4 digits)")
    answer = input("    keep it anyway? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def run(  # noqa: PLR0912, PLR0915 - a prompt loop; splitting it hides the flow
    images: list[Path],
    truth: TruthFile,
    *,
    root: Path,
    show: bool,
    assume_yes: bool,
) -> int:
    """Label ``images``. Returns a process exit code."""
    print(f"\n{len(images)} image(s) to label -> {truth.path}")
    print(
        f"already labelled: {len(truth.labels)} "
        f"({truth.positives} positive, {truth.negatives} negative)\n"
    )
    print(BANNER)

    index = 0
    done = 0
    skipped = 0
    while index < len(images):
        image = images[index]
        suggestion = predicted_plate(image)
        position = f"[{index + 1}/{len(images)}]"

        print(f"{position} {image}")
        if show:
            open_image(image)

        prompt = f"  plate [{suggestion}]: " if suggestion else "  plate: "
        try:
            entry = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            # Ctrl-C / Ctrl-D at the prompt is a normal way to stop. Everything
            # decided so far is already on disk.
            print("\n\ninterrupted -- everything decided so far is saved.")
            break

        command = entry.lower()
        if command == "q":
            break
        if command == "s":
            skipped += 1
            index += 1
            continue
        if command == "b":
            if index == 0:
                print("  (already at the first image)\n")
                continue
            index -= 1
            truth.forget(images[index])
            done = max(0, done - 1)
            print("  (re-doing the previous image)\n")
            continue
        if command == "n":
            truth.record(image, NEGATIVE, root=root)
            print("  -> no plate\n")
            done += 1
            index += 1
            continue

        plate = clean(entry) if entry else suggestion
        if not plate:
            print("  ! nothing entered and no suggestion to accept; use n or s\n")
            continue
        if not confirm_odd(plate, assume_yes=assume_yes):
            print("  (not saved -- type it again)\n")
            continue

        truth.record(image, plate, root=root)
        print(f"  -> {plate}\n")
        done += 1
        index += 1

    print(
        f"\nlabelled {done} this session ({skipped} skipped). "
        f"{len(truth.labels)} total in {truth.path} "
        f"({truth.positives} positive, {truth.negatives} negative)."
    )
    if truth.labels:
        print(
            "\nMeasure against it:\n"
            f"  python scripts/evaluate.py --images {root} "
            f"--truth {truth.path} --device cuda"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--images",
        type=Path,
        default=REPO_ROOT / "data" / "snapshots",
        help="Directory of images to label (searched recursively), or one image.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "data" / "ocr_ground_truth.json",
        help="Ground-truth file to create or extend.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Stop after this many (0 = all).")
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Label in random order. Use with --limit: a chronological prefix of "
        "one camera's day is not a sample of the site.",
    )
    parser.add_argument("--seed", type=int, default=0, help="Seed for --shuffle.")
    parser.add_argument(
        "--review",
        action="store_true",
        help="Include images that are already labelled, to check or change them.",
    )
    parser.add_argument("--show", action="store_true", help="Open each image in a viewer.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Do not ask for confirmation on a label that is not a valid TR plate.",
    )
    args = parser.parse_args(argv)

    root = args.images.expanduser()
    truth = TruthFile.load(args.out.expanduser())

    images = find_images(root)
    if not images:
        print(f"No images found under {root}.", file=sys.stderr)
        return 1
    if not args.review:
        images = [image for image in images if image.name not in truth.labels]
    if args.shuffle:
        random.Random(args.seed).shuffle(images)
    if args.limit > 0:
        images = images[: args.limit]

    if not images:
        print(
            f"Every image under {root} is already in {truth.path}. "
            "Pass --review to go through them again."
        )
        return 0

    try:
        return run(images, truth, root=root, show=args.show, assume_yes=args.yes)
    except KeyboardInterrupt:
        # Also caught at the prompt; this is the window between images.
        print("\ninterrupted -- everything decided so far is saved.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
