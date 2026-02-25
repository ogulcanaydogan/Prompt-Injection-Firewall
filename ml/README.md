# ML Training Pipeline

Fine-tune DistilBERT for prompt injection detection and export to ONNX for production inference.

## Overview

This pipeline trains a binary classifier on top of `distilbert-base-uncased` to detect prompt injection attacks. The model is exported to ONNX format with INT8 quantization for efficient inference in the Go-based PIF detection engine.

```
train.py ──▶ Fine-tuned Model ──▶ export_onnx.py ──▶ ONNX + INT8 ──▶ evaluate.py
                (PyTorch)              (Optimum)        (~65 MB)        (Benchmark)
```

## Requirements

- Python 3.10+
- CUDA GPU recommended (training works on CPU but takes longer)

```bash
cd ml/
pip install -r requirements.txt
```

## Training

```bash
python train.py
```

**Training data:** [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections) from Hugging Face Hub.

**Test data:** PIF benchmark dataset (`benchmarks/dataset/`) — 210 samples (100 benign + 110 injection) curated from real-world attacks.

**Hyperparameters:**

| Parameter | Value |
|-----------|-------|
| Base model | `distilbert-base-uncased` |
| Max sequence length | 256 tokens |
| Epochs | 5 |
| Batch size | 16 |
| Learning rate | 2e-5 |
| Weight decay | 0.01 |
| Metric for best model | F1 score |

**Output:**

```
output/
├── best/               # Best model checkpoint (PyTorch)
│   ├── model.safetensors
│   ├── config.json
│   ├── tokenizer.json
│   └── ...
└── results/
    ├── metrics.json    # Training & evaluation metrics
    └── logs/           # TensorBoard-compatible logs
```

## ONNX Export

After training, export the model to ONNX with INT8 quantization:

```bash
python export_onnx.py [--model-dir ./output/best] [--output-dir ./output/onnx]
```

This script:
1. Exports the PyTorch model to ONNX format using Hugging Face Optimum
2. Applies INT8 dynamic quantization (~50% size reduction)
3. Validates the exported model against test cases

**Output:**

```
output/onnx/
├── model.onnx          # Full ONNX model (~130 MB)
└── quantized/
    ├── model_quantized.onnx  # INT8 quantized (~65 MB)
    ├── config.json
    ├── tokenizer.json
    └── tokenizer_config.json
```

## Evaluation

Run standalone evaluation against the PIF benchmark dataset:

```bash
python evaluate.py [--model-dir ./output/onnx/quantized]
```

Reports:
- Accuracy, F1, Precision, Recall
- Confusion matrix (TN, FP, FN, TP)
- Per-category detection rates (10 attack categories)
- False positive analysis
- Missed detection analysis

**PIF targets:** Detection rate ≥ 80%, False positive rate ≤ 10%.

## Upload to Hugging Face Hub

After training and export, upload the quantized model:

```bash
huggingface-cli login
huggingface-cli upload ogulcanaydogan/pif-distilbert-injection-classifier output/onnx/quantized/
```

The Go ML detector downloads the model from the Hub at runtime:

```bash
# In PIF
pif scan --model ogulcanaydogan/pif-distilbert-injection-classifier "test prompt"
```

## Model Architecture

```
Input Text
    │
    ▼
WordPiece Tokenizer (max 256 tokens)
    │
    ▼
DistilBERT (6 layers, 768 hidden, 12 heads)
    │
    ▼
Classification Head (768 → 2)
    │
    ▼
Softmax → [BENIGN, INJECTION]
```

**Label mapping:**
- `0` → `BENIGN` — safe, legitimate prompts
- `1` → `INJECTION` — prompt injection attacks

## Integration with PIF

The ONNX model is loaded by the Go `MLDetector` (behind the `ml` build tag) using ONNX Runtime. The detector maps model confidence to PIF severity levels:

| Confidence | Severity |
|------------|----------|
| ≥ 0.95 | Critical |
| ≥ 0.90 | High |
| ≥ 0.85 | Medium |
| ≥ 0.75 | Low |
| < 0.75 | Info (below threshold) |

In the ensemble, the ML detector runs alongside the regex detector with configurable weights (default: regex 0.6, ML 0.4).
