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

os.environ["ROBOFLOW_API_KEY"]  = userdata.get("ROBOFLOW_API_KEY")
os.environ["ROBOFLOW_WORKSPACE"] = "your-workspace"
os.environ["ROBOFLOW_PROJECT"]   = "turkish-license-plates"
os.environ["ROBOFLOW_VERSION"]   = "1"
```

Already have a YOLO-format dataset? Skip this step and pass `--data path/to/data.yaml`
in step 4 instead.

### 4. Train

```python
!python scripts/train_plate_detector.py --device 0
```

Defaults: `imgsz=640 epochs=100 batch=16 patience=20`, horizontal flip disabled (a
mirrored plate is not a plate). Override any of them on the command line, e.g.
`--epochs 200 --batch 8`.

The script copies `best.pt` to `models/plate_yolov8n.pt` when it finishes.

### 5. Download the weights

```python
from google.colab import files
files.download("models/plate_yolov8n.pt")
```

### 6. Install locally

```bash
mv ~/Downloads/plate_yolov8n.pt models/plate_yolov8n.pt
python scripts/fetch_models.py   # confirms the custom model is active
```

Restart the API/pipeline. No config change is needed — `models/plate_yolov8n.pt` is
already the configured path.

---

### Notes

- **Colab disconnects kill the run.** For long trainings, mount Drive first
  (`from google.colab import drive; drive.mount('/content/drive')`) and pass
  `--project /content/drive/MyDrive/lpr_runs` so checkpoints survive.
- **Resume** an interrupted run: `!yolo detect train resume model=runs/detect/train/weights/last.pt`
- **Check it before deploying it:** `!yolo detect val model=models/plate_yolov8n.pt data=<data.yaml>`.
  Aim for mAP50 > 0.90 on plates; below that the voting layer will be doing damage control.
- **Out of memory?** Lower `--batch` (16 → 8 → 4) before lowering `--imgsz` — dropping
  resolution costs small-object recall, which is exactly what plates are.
- Curves, confusion matrix and per-epoch metrics land in the run directory
  (`runs/detect/train/`).
