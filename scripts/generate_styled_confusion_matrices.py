#!/usr/bin/env python3
"""
Generate publication-quality confusion matrices matching the exact reference style:
- Row-normalized color intensity (Share of true class: 0% to 100%)
- Clean continuous blue gradient with white grid separation
- Cell format: Bold raw count (line 1) + Percentage of true class (line 2)
- Zero values formatted as muted plain '0'
- Y-axis: Full class names; X-axis: Acronyms / short labels
- Clean colorbar titled 'Share of true class (%)'
- Both English (paper) and Vietnamese (thesis/report) versions
- Output formats: 300 DPI PNG and vector PDF
"""

import shutil
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

# Directories
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR if SCRIPT_DIR.name == "PRISM" else (SCRIPT_DIR.parent if SCRIPT_DIR.parent.name == "PRISM" else SCRIPT_DIR.parents[1])

OUT_DIRS = [
    REPO_ROOT / "PRISM-PROJECT" / "paper" / "figures",
    REPO_ROOT / "PRISM-PROJECT" / "artifacts",
    REPO_ROOT / "NSS2026_PRISM" / "figures",
    REPO_ROOT / "report_latex" / "img",
    REPO_ROOT / "artifacts",
]

for d in OUT_DIRS:
    d.mkdir(parents=True, exist_ok=True)

# ----------------- Exact Data -----------------
# (a) Five-class GNNMHAv2 (n = 1,949)
CM_5CLASS = np.array([
    [253,   0,   1, 114,   3],
    [  2, 237,   1, 119,   0],
    [  0,   0, 169, 135,   0],
    [  0,   0,   4, 442,   2],
    [  0,   0,   2, 122, 343]
])

# (b) Stage-A binary gate (n = 3,669)
CM_BINARY = np.array([
    [2773,  359],
    [  35,  502]
])

# Styling constants matching the reference image
BLUE_PALETTE = ['#ffffff', '#e8f2f9', '#a2cbe6', '#4192c7', '#0c6ca8']
CMAP = mcolors.LinearSegmentedColormap.from_list('share_blues', BLUE_PALETTE)
NORM = mcolors.Normalize(vmin=0, vmax=100)

COLOR_DARK_TEXT = '#09233b'
COLOR_MUTED_ZERO = '#5d7182'
COLOR_BORDER = '#526e85'


def save_fig_to_all(fig, basename: str):
    """Save figure to all relevant project locations in both PNG and PDF."""
    fig.tight_layout()
    for d in OUT_DIRS:
        if d.exists():
            fig.savefig(d / f"{basename}.png", dpi=300, bbox_inches="tight")
            fig.savefig(d / f"{basename}.pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"  -> Saved {basename}.png & .pdf")


def render_matrix_ax(ax, cm, x_labels, y_labels, x_title, y_title, title=None):
    """Render a single confusion matrix heatmap matching the reference style."""
    row_sums = cm.sum(axis=1, keepdims=True)
    cm_pct = np.divide(cm, row_sums, out=np.zeros_like(cm, dtype=float), where=row_sums != 0) * 100

    n_rows, n_cols = cm.shape
    im = ax.imshow(cm_pct, cmap=CMAP, norm=NORM, origin="upper")

    # Text annotations in each cell
    for r in range(n_rows):
        for c in range(n_cols):
            val = cm[r, c]
            pct = cm_pct[r, c]
            if val == 0:
                ax.text(c, r, "0", ha="center", va="center", color=COLOR_MUTED_ZERO, fontsize=11)
            else:
                txt_color = "#ffffff" if pct >= 50.0 else COLOR_DARK_TEXT
                ax.text(c, r - 0.12, f"{val:,}", ha="center", va="center",
                        color=txt_color, fontweight="bold", fontsize=11.5)
                ax.text(c, r + 0.18, f"{pct:.1f}%", ha="center", va="center",
                        color=txt_color, fontweight="normal", fontsize=9.5)

    # Grid separation
    ax.set_xticks(np.arange(-0.5, n_cols, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, n_rows, 1), minor=True)
    ax.grid(which="minor", color="white", linestyle="-", linewidth=1.5)
    ax.tick_params(which="minor", bottom=False, left=False)

    # Tick labels
    ax.set_xticks(range(n_cols))
    ax.set_xticklabels(x_labels, fontsize=11, color=COLOR_DARK_TEXT)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(y_labels, fontsize=11, color=COLOR_DARK_TEXT)
    ax.tick_params(which="major", bottom=False, left=False, pad=6)

    # Axis titles
    ax.set_xlabel(x_title, fontsize=11.5, color=COLOR_DARK_TEXT, labelpad=10)
    ax.set_ylabel(y_title, fontsize=11.5, color=COLOR_DARK_TEXT, labelpad=10)
    if title:
        ax.set_title(title, fontsize=12, fontweight="bold", color=COLOR_DARK_TEXT, pad=10)

    # Borders
    for spine in ax.spines.values():
        spine.set_edgecolor(COLOR_BORDER)
        spine.set_linewidth(1.0)

    return im


def plot_5class(lang="en"):
    """Generate standalone 5-class confusion matrix matching reference image."""
    fig, ax = plt.subplots(figsize=(6.2, 4.0), dpi=300)

    if lang == "en":
        x_labels = ["RE", "IO", "AC", "UR", "FR"]
        y_labels = ["Reentrancy", "Integer overflow", "Access control", "Unchecked return", "Front-running"]
        x_title = "Predicted class"
        y_title = "True class"
        cbar_title = "Share of true class (%)"
        basename = "confusion_matrix_5class_en"
    else:
        x_labels = ["RE", "IO", "AC", "UR", "FR"]
        y_labels = ["Reentrancy", "Integer overflow", "Access control", "Unchecked return", "Front-running"]
        x_title = "Nhãn dự đoán"
        y_title = "Nhãn thực"
        cbar_title = "Tỷ lệ theo nhãn thực (%)"
        basename = "confusion_matrix_5class_vn"

    im = render_matrix_ax(ax, CM_5CLASS, x_labels, y_labels, x_title, y_title)

    from mpl_toolkits.axes_grid1 import make_axes_locatable
    divider = make_axes_locatable(ax)
    cax = divider.append_axes("right", size="6%", pad=0.15)
    cbar = fig.colorbar(im, cax=cax)
    cbar.set_ticks([0, 25, 50, 75, 100])
    cbar.set_ticklabels(["0", "25", "50", "75", "100"])
    cbar.ax.tick_params(labelsize=10, colors=COLOR_DARK_TEXT, length=3)
    cbar.outline.set_edgecolor(COLOR_BORDER)
    cbar.outline.set_linewidth(0.8)
    cbar.set_label(cbar_title, fontsize=11.5, color=COLOR_DARK_TEXT, labelpad=8)

    save_fig_to_all(fig, basename)


def plot_binary(lang="en"):
    """Generate standalone Stage-A binary gate confusion matrix matching reference style."""
    fig, ax = plt.subplots(figsize=(4.5, 3.8), dpi=300)

    if lang == "en":
        x_labels = ["Vuln.", "Safe"]
        y_labels = ["Vulnerable", "Safe"]
        x_title = "Predicted class"
        y_title = "True class"
        cbar_title = "Share of true class (%)"
        basename = "confusion_matrix_binary_en"
    else:
        x_labels = ["Lỗ hổng", "An toàn"]
        y_labels = ["Có lỗ hổng", "An toàn"]
        x_title = "Nhãn dự đoán"
        y_title = "Nhãn thực"
        cbar_title = "Tỷ lệ theo nhãn thực (%)"
        basename = "confusion_matrix_binary_vn"

    im = render_matrix_ax(ax, CM_BINARY, x_labels, y_labels, x_title, y_title)

    from mpl_toolkits.axes_grid1 import make_axes_locatable
    divider = make_axes_locatable(ax)
    cax = divider.append_axes("right", size="7%", pad=0.15)
    cbar = fig.colorbar(im, cax=cax)
    cbar.set_ticks([0, 25, 50, 75, 100])
    cbar.set_ticklabels(["0", "25", "50", "75", "100"])
    cbar.ax.tick_params(labelsize=10, colors=COLOR_DARK_TEXT, length=3)
    cbar.outline.set_edgecolor(COLOR_BORDER)
    cbar.outline.set_linewidth(0.8)
    cbar.set_label(cbar_title, fontsize=11.5, color=COLOR_DARK_TEXT, labelpad=8)

    save_fig_to_all(fig, basename)


def plot_combined(lang="en"):
    """Generate combined side-by-side figure (a) + (b) with unified reference style."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.2, 4.4), dpi=300,
                                   gridspec_kw={"width_ratios": [1.32, 1.0], "wspace": 0.38})

    if lang == "en":
        x_labels_5 = ["RE", "IO", "AC", "UR", "FR"]
        y_labels_5 = ["Reentrancy", "Integer overflow", "Access control", "Unchecked return", "Front-running"]
        x_labels_b = ["Vuln.", "Safe"]
        y_labels_b = ["Vulnerable", "Safe"]
        x_title = "Predicted class"
        y_title = "True class"
        title_a = "(a) Five-class GNNMHAv2 ($n = 1{,}949$)"
        title_b = "(b) Stage-A binary gate ($n = 3{,}669$)"
        cbar_title = "Share of true class (%)"
        basename = "confusion_matrices_combined_en"
    else:
        x_labels_5 = ["RE", "IO", "AC", "UR", "FR"]
        y_labels_5 = ["Reentrancy", "Integer overflow", "Access control", "Unchecked return", "Front-running"]
        x_labels_b = ["Lỗ hổng", "An toàn"]
        y_labels_b = ["Có lỗ hổng", "An toàn"]
        x_title = "Nhãn dự đoán"
        y_title = "Nhãn thực"
        title_a = "(a) Đa lớp — GNNMHAv2 ($n = 1{,}949$)"
        title_b = "(b) Nhị phân — Stage-A ($n = 3{,}669$)"
        cbar_title = "Tỷ lệ theo nhãn thực (%)"
        basename = "confusion_matrices_combined_vn"

    im1 = render_matrix_ax(ax1, CM_5CLASS, x_labels_5, y_labels_5, x_title, y_title, title=title_a)
    im2 = render_matrix_ax(ax2, CM_BINARY, x_labels_b, y_labels_b, x_title, y_title, title=title_b)

    from mpl_toolkits.axes_grid1 import make_axes_locatable
    divider = make_axes_locatable(ax2)
    cax = divider.append_axes("right", size="7%", pad=0.18)
    cbar = fig.colorbar(im2, cax=cax)
    cbar.set_ticks([0, 25, 50, 75, 100])
    cbar.set_ticklabels(["0", "25", "50", "75", "100"])
    cbar.ax.tick_params(labelsize=10, colors=COLOR_DARK_TEXT, length=3)
    cbar.outline.set_edgecolor(COLOR_BORDER)
    cbar.outline.set_linewidth(0.8)
    cbar.set_label(cbar_title, fontsize=11.5, color=COLOR_DARK_TEXT, labelpad=8)

    save_fig_to_all(fig, basename)


def sync_default_names():
    """Ensure standard filenames used by papers/reports point to the freshly styled versions."""
    for d in OUT_DIRS:
        if not d.exists():
            continue
        en_combined = d / "confusion_matrices_combined_en.png"
        if en_combined.exists():
            shutil.copy2(en_combined, d / "confusion_matrices_combined.png")
            shutil.copy2(d / "confusion_matrices_combined_en.pdf", d / "confusion_matrices_combined.pdf")
        en_5class = d / "confusion_matrix_5class_en.png"
        if en_5class.exists():
            shutil.copy2(en_5class, d / "confusion_matrix_5class.png")
            shutil.copy2(d / "confusion_matrix_5class_en.pdf", d / "confusion_matrix_5class.pdf")
        en_binary = d / "confusion_matrix_binary_en.png"
        if en_binary.exists():
            shutil.copy2(en_binary, d / "confusion_matrix_binary.png")
            shutil.copy2(d / "confusion_matrix_binary_en.pdf", d / "confusion_matrix_binary.pdf")
    print("  -> Synced default filenames for LaTeX compilation.")


if __name__ == "__main__":
    print("=== Generating High-Fidelity Styled Confusion Matrices ===")
    plot_5class("en")
    plot_5class("vn")
    plot_binary("en")
    plot_binary("vn")
    plot_combined("en")
    plot_combined("vn")
    sync_default_names()
    print("✅ All figures generated successfully in reference style!")
