#!/usr/bin/env python3
"""
Generate publication-quality confusion matrices in the matplotlib/seaborn heatmap style
with colorbar, Blues colormap, bold values, and clean layout:
1. (a) 5-class confusion matrix (n = 1,949)
2. (b) Stage-A binary gate confusion matrix (n = 3,669)
3. Combined side-by-side figure (a) + (b)

Generates both Vietnamese (thesis/report) and English (paper/international) versions,
saving both 300 DPI PNG and vector PDF.
"""

import shutil
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Directories
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR_PAPER = PROJECT_ROOT / "paper" / "figures"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
for d in [OUT_DIR_PAPER, ARTIFACTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Data
CM_5CLASS = np.array([
    [255,   1,   2, 110,   3],
    [  0, 237,   1, 121,   0],
    [  0,   0, 166, 138,   0],
    [  0,   1,   1, 444,   2],
    [  0,   0,   0, 124, 343]
])

CM_BINARY = np.array([
    [2773,  359],
    [  35,  502]
])


LABELS_5CLASS_VN = ["Reentrancy", "Integer\noverflow", "Access\ncontrol", "Unchecked\nreturn", "Front\nrunning"]
LABELS_5CLASS_EN = ["Reentrancy", "Integer\noverflow", "Access\ncontrol", "Unchecked\nreturn", "Front\nrunning"]
LABELS_BINARY = ["Vulnerable", "Safe"]


def save_fig_all(fig, basename: str):
    """Save to paper figures and artifacts in PNG (300 dpi) and PDF."""
    fig.tight_layout()
    for d in [OUT_DIR_PAPER, ARTIFACTS_DIR]:
        png_path = d / f"{basename}.png"
        pdf_path = d / f"{basename}.pdf"
        fig.savefig(png_path, dpi=300, bbox_inches="tight")
        fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> Saved {basename}.png & .pdf")


def plot_5class(lang="vn"):
    fig, ax = plt.subplots(figsize=(6.4, 5.2), dpi=300)
    image = ax.imshow(CM_5CLASS, cmap="Blues")

    for r in range(CM_5CLASS.shape[0]):
        for c in range(CM_5CLASS.shape[1]):
            val = CM_5CLASS[r, c]
            color = "white" if val > CM_5CLASS.max() * 0.55 else "black"
            ax.text(c, r, f"{val:,}", ha="center", va="center", color=color, fontweight="bold", fontsize=11)

    labels = LABELS_5CLASS_VN if lang == "vn" else LABELS_5CLASS_EN
    ax.set_xticks(range(5))
    ax.set_yticks(range(5))
    ax.set_xticklabels(labels, fontsize=10.5)
    ax.set_yticklabels(labels, fontsize=10.5)

    if lang == "vn":
        ax.set_xlabel("Nhãn dự đoán", fontsize=11, labelpad=6)
        ax.set_ylabel("Nhãn thực", fontsize=11, labelpad=6)
        ax.set_title("Ma trận nhầm lẫn — v5_top5_focal (n=1,949)", fontsize=12, pad=10)
        cbar = fig.colorbar(image, ax=ax)
        cbar.set_label("Số lượng mẫu kiểm thử", fontsize=11, labelpad=8)
        basename = "confusion_matrix_5class_vn"
    else:
        ax.set_xlabel("Predicted class", fontsize=11, labelpad=6)
        ax.set_ylabel("True class", fontsize=11, labelpad=6)
        ax.set_title("(a) Five-class GNNMHAv2 ($n = 1,949$)", fontsize=12, fontweight="bold", pad=10)
        cbar = fig.colorbar(image, ax=ax)
        cbar.set_label("Number of test samples", fontsize=11, labelpad=8)
        basename = "confusion_matrix_5class_en"

    cbar.ax.tick_params(labelsize=10)
    save_fig_all(fig, basename)


def plot_binary(lang="vn"):
    fig, ax = plt.subplots(figsize=(5.8, 4.4), dpi=300)
    im = ax.imshow(CM_BINARY, cmap="Blues")

    for r in range(2):
        for c in range(2):
            val = CM_BINARY[r, c]
            color = "white" if val > CM_BINARY.max() * 0.5 else "black"
            ax.text(c, r, f"{val:,}", ha="center", va="center", color=color, fontweight="bold", fontsize=12)

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(LABELS_BINARY, fontsize=11)
    ax.set_yticklabels(LABELS_BINARY, fontsize=11)

    if lang == "vn":
        ax.set_xlabel("Nhãn dự đoán", fontsize=11, labelpad=6)
        ax.set_ylabel("Nhãn thực", fontsize=11, labelpad=6)
        ax.set_title("Ma trận nhầm lẫn nhị phân — v5_binary (n=3,669)", fontsize=12, pad=10)
        cbar = fig.colorbar(im, ax=ax)
        cbar.set_label("Số lượng mẫu kiểm thử", fontsize=11, labelpad=8)
        basename = "confusion_matrix_binary_vn"
    else:
        ax.set_xlabel("Predicted class", fontsize=11, labelpad=6)
        ax.set_ylabel("True class", fontsize=11, labelpad=6)
        ax.set_title("(b) Stage-A binary gate ($n = 3,669$)", fontsize=12, fontweight="bold", pad=10)
        cbar = fig.colorbar(im, ax=ax)
        cbar.set_label("Number of test samples", fontsize=11, labelpad=8)
        basename = "confusion_matrix_binary_en"

    cbar.ax.tick_params(labelsize=10)
    save_fig_all(fig, basename)


def plot_combined(lang="vn"):
    """Combined side-by-side figure with both matrices and individual colorbars."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.5, 4.8), dpi=300,
                                   gridspec_kw={'width_ratios': [1.15, 1.0]})

    # (a) 5-class
    im1 = ax1.imshow(CM_5CLASS, cmap="Blues")
    for r in range(5):
        for c in range(5):
            val = CM_5CLASS[r, c]
            color = "white" if val > CM_5CLASS.max() * 0.55 else "black"
            ax1.text(c, r, f"{val:,}", ha="center", va="center", color=color, fontweight="bold", fontsize=10)

    labels = LABELS_5CLASS_VN if lang == "vn" else LABELS_5CLASS_EN
    ax1.set_xticks(range(5))
    ax1.set_yticks(range(5))
    ax1.set_xticklabels(labels, fontsize=9.5)
    ax1.set_yticklabels(labels, fontsize=9.5)

    # (b) binary
    im2 = ax2.imshow(CM_BINARY, cmap="Blues")
    for r in range(2):
        for c in range(2):
            val = CM_BINARY[r, c]
            color = "white" if val > CM_BINARY.max() * 0.5 else "black"
            ax2.text(c, r, f"{val:,}", ha="center", va="center", color=color, fontweight="bold", fontsize=11)

    ax2.set_xticks([0, 1])
    ax2.set_yticks([0, 1])
    ax2.set_xticklabels(LABELS_BINARY, fontsize=10.5)
    ax2.set_yticklabels(LABELS_BINARY, fontsize=10.5)

    if lang == "vn":
        ax1.set_xlabel("Nhãn dự đoán", fontsize=10.5, labelpad=6)
        ax1.set_ylabel("Nhãn thực", fontsize=10.5, labelpad=6)
        ax1.set_title("(a) Đa lớp — v5_top5_focal (n=1,949)", fontsize=11, fontweight="bold", pad=8)
        cb1 = fig.colorbar(im1, ax=ax1, fraction=0.046, pad=0.04)
        cb1.set_label("Số lượng mẫu", fontsize=10)

        ax2.set_xlabel("Nhãn dự đoán", fontsize=10.5, labelpad=6)
        ax2.set_ylabel("Nhãn thực", fontsize=10.5, labelpad=6)
        ax2.set_title("(b) Nhị phân — v5_binary (n=3,669)", fontsize=11, fontweight="bold", pad=8)
        cb2 = fig.colorbar(im2, ax=ax2, fraction=0.046, pad=0.04)
        cb2.set_label("Số lượng mẫu", fontsize=10)
        basename = "confusion_matrices_combined_vn"
    else:
        ax1.set_xlabel("Predicted class", fontsize=10.5, labelpad=6)
        ax1.set_ylabel("True class", fontsize=10.5, labelpad=6)
        ax1.set_title("(a) Five-class GNNMHAv2 ($n = 1,949$)", fontsize=11, fontweight="bold", pad=8)
        cb1 = fig.colorbar(im1, ax=ax1, fraction=0.046, pad=0.04)
        cb1.set_label("Test samples", fontsize=10)

        ax2.set_xlabel("Predicted class", fontsize=10.5, labelpad=6)
        ax2.set_ylabel("True class", fontsize=10.5, labelpad=6)
        ax2.set_title("(b) Stage-A binary gate ($n = 3,669$)", fontsize=11, fontweight="bold", pad=8)
        cb2 = fig.colorbar(im2, ax=ax2, fraction=0.046, pad=0.04)
        cb2.set_label("Test samples", fontsize=10)
        basename = "confusion_matrices_combined_en"

    save_fig_all(fig, basename)


if __name__ == "__main__":
    print("=== Generating Heatmap Style Confusion Matrices ===")
    plot_5class("vn")
    plot_binary("vn")
    plot_combined("vn")

    plot_5class("en")
    plot_binary("en")
    plot_combined("en")

    # Sync default paper figure names
    shutil.copy2(OUT_DIR_PAPER / "confusion_matrices_combined_en.png", OUT_DIR_PAPER / "confusion_matrices_combined.png")
    shutil.copy2(OUT_DIR_PAPER / "confusion_matrix_5class_en.png", OUT_DIR_PAPER / "confusion_matrix_5class.png")
    shutil.copy2(OUT_DIR_PAPER / "confusion_matrix_binary_en.png", OUT_DIR_PAPER / "confusion_matrix_binary.png")
    shutil.copy2(OUT_DIR_PAPER / "confusion_matrices_combined_en.png", ARTIFACTS_DIR / "confusion_matrices_combined.png")

    print("✅ All styled confusion matrices successfully generated!")
