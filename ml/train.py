#!/usr/bin/env python3
"""
PIF ML Training Pipeline — Fine-tune DistilBERT for Prompt Injection Detection

This script fine-tunes distilbert-base-uncased for binary classification:
  - Label 0: benign
  - Label 1: injection

Training data: deepset/prompt-injections dataset from HuggingFace Hub
Test data:     PIF benchmark dataset (benchmarks/dataset/)

Usage:
    cd ml/
    pip install -r requirements.txt
    python train.py

Output:
    ./output/          - Fine-tuned model checkpoint
    ./output/results/  - Evaluation metrics and training logs
"""

import json
import os
import sys
from pathlib import Path

import numpy as np
from datasets import Dataset, DatasetDict, load_dataset
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)


MODEL_NAME = "distilbert-base-uncased"
OUTPUT_DIR = "./output"
RESULTS_DIR = "./output/results"
BENCHMARK_DIR = "../benchmarks/dataset"
MAX_LENGTH = 256
EPOCHS = 5
BATCH_SIZE = 16
LEARNING_RATE = 2e-5


def load_hf_training_data():
    """Load the deepset/prompt-injections dataset for training."""
    print("Loading deepset/prompt-injections dataset...")
    ds = load_dataset("deepset/prompt-injections")

    # The dataset has 'text' and 'label' columns
    # label 0 = benign, label 1 = injection
    train_ds = ds["train"]
    print(f"  Training samples: {len(train_ds)}")

    # Check label distribution
    labels = train_ds["label"]
    print(f"  Benign: {labels.count(0)}, Injection: {labels.count(1)}")

    return train_ds


def load_pif_benchmark():
    """Load PIF benchmark dataset as held-out test set."""
    print("Loading PIF benchmark dataset...")

    benign_path = Path(BENCHMARK_DIR) / "benign.json"
    injection_path = Path(BENCHMARK_DIR) / "injections.json"

    if not benign_path.exists() or not injection_path.exists():
        print(f"  Warning: Benchmark files not found at {BENCHMARK_DIR}")
        print("  Falling back to HF test split")
        return None

    with open(benign_path) as f:
        benign_data = json.load(f)
    with open(injection_path) as f:
        injection_data = json.load(f)

    texts = []
    labels = []

    for sample in benign_data:
        texts.append(sample["text"])
        labels.append(0)

    for sample in injection_data:
        texts.append(sample["text"])
        labels.append(1)

    test_ds = Dataset.from_dict({"text": texts, "label": labels})
    print(f"  Test samples: {len(test_ds)} (benign: {len(benign_data)}, injection: {len(injection_data)})")

    return test_ds


def compute_metrics(eval_pred):
    """Compute classification metrics for the Trainer."""
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)

    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1": f1_score(labels, predictions, average="binary"),
        "precision": precision_score(labels, predictions, average="binary"),
        "recall": recall_score(labels, predictions, average="binary"),
    }


def main():
    print("=" * 60)
    print("PIF ML Training Pipeline")
    print("=" * 60)
    print(f"Model:       {MODEL_NAME}")
    print(f"Max length:  {MAX_LENGTH}")
    print(f"Epochs:      {EPOCHS}")
    print(f"Batch size:  {BATCH_SIZE}")
    print(f"LR:          {LEARNING_RATE}")
    print()

    # Create output directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Load data
    train_ds = load_hf_training_data()
    test_ds = load_pif_benchmark()

    if test_ds is None:
        # Fallback: use HF test split
        ds = load_dataset("deepset/prompt-injections")
        test_ds = ds["test"]

    # Load tokenizer and model
    print(f"\nLoading {MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2,
        id2label={0: "BENIGN", 1: "INJECTION"},
        label2id={"BENIGN": 0, "INJECTION": 1},
    )

    # Tokenize datasets
    def tokenize_fn(examples):
        return tokenizer(
            examples["text"],
            padding="max_length",
            truncation=True,
            max_length=MAX_LENGTH,
        )

    print("Tokenizing datasets...")
    train_tokenized = train_ds.map(tokenize_fn, batched=True, remove_columns=["text"])
    test_tokenized = test_ds.map(tokenize_fn, batched=True, remove_columns=["text"])

    train_tokenized.set_format("torch")
    test_tokenized.set_format("torch")

    # Training arguments
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        learning_rate=LEARNING_RATE,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_dir=os.path.join(RESULTS_DIR, "logs"),
        logging_steps=50,
        report_to="none",  # disable wandb/mlflow
        seed=42,
    )

    # Create Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_tokenized,
        eval_dataset=test_tokenized,
        compute_metrics=compute_metrics,
    )

    # Train
    print("\nStarting training...")
    train_result = trainer.train()

    # Save best model
    trainer.save_model(os.path.join(OUTPUT_DIR, "best"))
    tokenizer.save_pretrained(os.path.join(OUTPUT_DIR, "best"))

    # Evaluate
    print("\nFinal evaluation on test set...")
    eval_result = trainer.evaluate()
    print(f"  Accuracy:  {eval_result['eval_accuracy']:.4f}")
    print(f"  F1:        {eval_result['eval_f1']:.4f}")
    print(f"  Precision: {eval_result['eval_precision']:.4f}")
    print(f"  Recall:    {eval_result['eval_recall']:.4f}")

    # Detailed classification report
    predictions = trainer.predict(test_tokenized)
    preds = np.argmax(predictions.predictions, axis=-1)
    labels = predictions.label_ids

    report = classification_report(
        labels, preds, target_names=["benign", "injection"], digits=4
    )
    print(f"\nClassification Report:\n{report}")

    cm = confusion_matrix(labels, preds)
    print(f"Confusion Matrix:\n{cm}")

    # Save metrics
    metrics = {
        "model": MODEL_NAME,
        "epochs": EPOCHS,
        "batch_size": BATCH_SIZE,
        "learning_rate": LEARNING_RATE,
        "max_length": MAX_LENGTH,
        "train_samples": len(train_ds),
        "test_samples": len(test_ds),
        "accuracy": float(eval_result["eval_accuracy"]),
        "f1": float(eval_result["eval_f1"]),
        "precision": float(eval_result["eval_precision"]),
        "recall": float(eval_result["eval_recall"]),
        "confusion_matrix": cm.tolist(),
        "train_loss": float(train_result.training_loss),
    }

    metrics_path = os.path.join(RESULTS_DIR, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nMetrics saved to {metrics_path}")

    print(f"\nBest model saved to {OUTPUT_DIR}/best/")
    print("Next step: python export_onnx.py")


if __name__ == "__main__":
    main()
