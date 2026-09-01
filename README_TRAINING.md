# Training the plate detector (Google Colab)

Fine-tunes YOLOv8n on Turkish plates and produces `models/plate_yolov8n.pt` — the file
`detection.model_path` points at. ~1–2 h on a free T4 for 100 epochs.

**Runtime → Change runtime type → T4 GPU** before you start. Training on Colab's CPU is
not worth attempting.

---

### 1. Install

```python
!pip install -q ultralytics roboflow
```

### 2. Get the code

```python
!git clone https://github.com/<you>/License-Plate-Recognition.git
%cd License-Plate-Recognition
```

### 3. Set the dataset env vars

Use Colab's **🔑 Secrets** panel for the key so it never lands in saved cell output:

```python
import os
from google.colab import userdata

os.environ["ROBOFLOW_API_KEY"] = userdata.get("ROBOFLOW_API_KEY")
os.environ["ROBOFLOW_WORKSPACE"] = "your-workspace"
os.environ["ROBOFLOW_PROJECT"] = "turkish-license-plates"
os.environ["ROBOFLOW_VERSION"] = "1"
```

Already have a YOLO-format dataset? Skip this step and pass `--data path/to/data.yaml`
in step 4 instead. No dataset at all yet?

```python
!python scripts/fetch_dataset.py --scaffold datasets/plates
```

creates the empty tree and prints the layout to fill in.

### 4. Check the dataset before you spend the GPU

```python
!python scripts/fetch_dataset.py --check datasets/plates/data.yaml
```

Seconds, and it catches the three mistakes that cost a whole training run because
each one produces a run that *completes* and reports a plausible number:

- an empty or missing validation split;
- a train/val leak — the same images in both, which makes every metric better and
  is invisible in the metrics themselves;
- labels in pixel coordinates instead of normalised 0–1, the classic converter bug.

`train_plate_detector.py` runs this check itself before training, so step 4 is really
just "see the answer early". `--skip-dataset-check` bypasses it; you almost never want to.

### 5. Train

```python
!python scripts/train_plate_detector.py --device 0 --min-map 0.85
```

Defaults: `imgsz=640 epochs=100 batch=16 patience=20`, horizontal flip disabled (a
mirrored plate is not a plate). Override any of them on the command line, e.g.
`--epochs 200 --batch 8`.

When it finishes the script prints the validation metrics, then does two things before
installing anything:

- **`--min-map`** refuses to install weights whose mAP@0.5 is below the floor. Without
  it a disappointing run silently replaces a better model.
- **Class-name verification** refuses to install weights the runtime would reject —
  a multi-class model with no plate class is the stock COCO baseline, which loads fine,
  detects people and chairs, and makes the pipeline fall back to contour detection.
  That is a failure that looks exactly like success.

Only then is `best.pt` copied to `models/plate_yolov8n.pt`, with the previous model kept
alongside as `.pt.bak`.

### 6. Download the weights

```python
from google.colab import files

files.download("models/plate_yolov8n.pt")
```

### 7. Install locally

```bash
mv ~/Downloads/plate_yolov8n.pt models/plate_yolov8n.pt
python scripts/fetch_models.py   # confirms the custom model is active
```

`fetch_models.py` compares the file against the stock baseline's SHA-256 and says so
loudly if they match — that is, if what you installed is the COCO model wearing the
plate model's name.

Restart the API/pipeline. No config change is needed — `models/plate_yolov8n.pt` is
already the configured path.

### 8. Measure the whole pipeline, not just the detector

`yolo detect val` scores boxes. It says nothing about whether the *string* was right,
which is the only thing the barrier acts on:

```bash
python scripts/evaluate.py --images eval/ --truth eval/truth.csv --device both
```

Reports plate accuracy, CER, wrong-plate rate, false-positive rate and CPU-vs-CUDA
latency. Include **negative samples** — images with no plate, written with an empty
plate column — or the false-positive rate cannot be measured, and it is the number
that decides whether the barrier opens for a stranger.

Add thresholds to turn it into a gate:

```bash
python scripts/evaluate.py --images eval/ --truth eval/truth.csv \
    --min-accuracy 0.95 --max-false-positive 0.005 --max-wrong-plate 0.02
```

---

### Notes

- **Colab disconnects kill the run.** For long trainings, mount Drive first
  (`from google.colab import drive; drive.mount('/content/drive')`) and pass
  `--project /content/drive/MyDrive/lpr_runs` so checkpoints survive.
- **Resume** an interrupted run: `!yolo detect train resume model=runs/detect/train/weights/last.pt`
- **Check it before deploying it:** `!yolo detect val model=models/plate_yolov8n.pt data=<data.yaml>`.
  Aim for mAP50 > 0.90 on plates; below that the voting layer will be doing damage control.
  Then run `scripts/evaluate.py` — mAP measures boxes, and the gate acts on strings.
- **Out of memory?** Lower `--batch` (16 → 8 → 4) before lowering `--imgsz` — dropping
  resolution costs small-object recall, which is exactly what plates are.
- Curves, confusion matrix and per-epoch metrics land in the run directory
  (`runs/detect/train/`).
