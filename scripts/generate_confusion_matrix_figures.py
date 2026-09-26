#!/usr/bin/env python3
"""
Generate Confusion Matrix figures for PRISM NSS 2026 & Thesis Reports:
- (a) Five-class GNNMHAv2 (n = 1,949)
- (b) Stage-A binary gate (n = 3,669)
- Combined figure (a) + (b)

Styling matches publication quality:
- Row-normalized color intensity ("Share of true class (%)" from 0% to 100%)
- Clean continuous blue gradient with white grid separation
- Cell format: Bold raw count (line 1) + Percentage of true class (line 2)
- Zero values formatted as muted plain '0' without percentage
- Y-axis: Full class names; X-axis: Acronyms ("RE", "IO", "AC", "UR", "FR")
- Clean colorbar titled 'Share of true class (%)'
- Both English (paper) and Vietnamese (thesis/report) versions
- Output formats: 300 DPI PNG and vector PDF
"""

import os
import shutil
import subprocess
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from mpl_toolkits.axes_grid1 import make_axes_locatable

# Base directories
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR if SCRIPT_DIR.name == "PRISM" else (SCRIPT_DIR.parent if SCRIPT_DIR.parent.name == "PRISM" else SCRIPT_DIR.parents[1])

OUT_DIRS = [
    REPO_ROOT / "PRISM-PROJECT" / "paper" / "figures",
    REPO_ROOT / "PRISM-PROJECT" / "artifacts",
    REPO_ROOT / "NSS2026_PRISM" / "figures",
    REPO_ROOT / "paper" / "figures",
    REPO_ROOT / "report_latex" / "img",
    REPO_ROOT / "artifacts",
]

for d in OUT_DIRS:
    d.mkdir(parents=True, exist_ok=True)

TIKZ_SRC_DIR = REPO_ROOT / "PRISM-PROJECT" / "paper" / "figures" / "src"

# ----------------- Exact Canonical Data -----------------
# (a) Five-class GNNMHAv2 (n = 1,949 from models/v5_top5_focal/raw_predictions.csv)
CLASSES_A_FULL = ["Reentrancy", "Integer overflow", "Access control", "Unchecked return", "Front-running"]
CLASSES_A_FULL_VN = ["Reentrancy", "Integer overflow", "Access control", "Unchecked return", "Front running"]
CLASSES_A_SHORT = ["RE", "IO", "AC", "UR", "FR"]

CM_A = np.array([
    [253,   0,   1, 114,   3],
    [  2, 237,   1, 119,   0],
    [  0,   0, 169, 135,   0],
    [  0,   0,   4, 442,   2],
    [  0,   0,   2, 122, 343]
])

# (b) Stage-A binary gate (n = 3,669)
CLASSES_B_EN = ["Vuln.", "Safe"]
CLASSES_B_VN = ["Lỗ hổng", "An toàn"]
CLASSES_B_Y_EN = ["Vulnerable", "Safe"]
CLASSES_B_Y_VN = ["Có lỗ hổng", "An toàn"]

CM_B = np.array([
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


def save_fig_to_all(fig, basename: str, extra_names=None):
    """Save figure to all relevant project locations in both PNG and PDF."""
    fig.tight_layout()
    names = [basename] + (extra_names or [])
    for d in OUT_DIRS:
        if d.exists():
            for name in names:
                fig.savefig(d / f"{name}.png", dpi=300, bbox_inches="tight")
                fig.savefig(d / f"{name}.pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"  -> Saved {basename} (and aliases: {extra_names}) to all target dirs")


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


def plot_matplotlib_five_class(lang="en", with_title=False):
    """Generate standalone 5-class confusion matrix matching reference image."""
    fig, ax = plt.subplots(figsize=(6.2, 4.0), dpi=300)

    if lang == "en":
        x_labels = CLASSES_A_SHORT
        y_labels = CLASSES_A_FULL
        x_title = "Predicted class"
        y_title = "True class"
        cbar_title = "Share of true class (%)"
        title = "(a) Five-class GNNMHAv2 ($n = 1,949$)" if with_title else None
        basename = "confusion_matrix_5class_en"
        extra_names = ["confusion_matrix_a_matplotlib", "confusion_matrix_5class"]
    else:
        x_labels = CLASSES_A_SHORT
        y_labels = CLASSES_A_FULL_VN
        x_title = "Nhãn dự đoán"
        y_title = "Nhãn thực"
        cbar_title = "Tỷ lệ theo nhãn thực (%)"
        title = "Ma trận nhầm lẫn — v5_top5_focal (n=1,949)" if with_title else None
        basename = "confusion_matrix_5class_vn"
        extra_names = ["confusion_matrix"] if not with_title else ["confusion_matrix_titled"]

    im = render_matrix_ax(ax, CM_A, x_labels, y_labels, x_title, y_title, title=title)

    divider = make_axes_locatable(ax)
    cax = divider.append_axes("right", size="6%", pad=0.15)
    cbar = fig.colorbar(im, cax=cax)
    cbar.set_ticks([0, 25, 50, 75, 100])
    cbar.set_ticklabels(["0", "25", "50", "75", "100"])
    cbar.ax.tick_params(labelsize=10, colors=COLOR_DARK_TEXT, length=3)
    cbar.outline.set_edgecolor(COLOR_BORDER)
    cbar.outline.set_linewidth(0.8)
    cbar.set_label(cbar_title, fontsize=11.5, color=COLOR_DARK_TEXT, labelpad=8)

    save_fig_to_all(fig, basename, extra_names=extra_names)


def plot_matplotlib_binary_gate(lang="en"):
    """Generate standalone Stage-A binary gate confusion matrix matching reference style."""
    fig, ax = plt.subplots(figsize=(4.5, 3.8), dpi=300)

    if lang == "en":
        x_labels = CLASSES_B_EN
        y_labels = CLASSES_B_Y_EN
        x_title = "Predicted class"
        y_title = "True class"
        cbar_title = "Share of true class (%)"
        basename = "confusion_matrix_binary_en"
        extra_names = ["confusion_matrix_b_matplotlib", "confusion_matrix_binary"]
    else:
        x_labels = CLASSES_B_VN
        y_labels = CLASSES_B_Y_VN
        x_title = "Nhãn dự đoán"
        y_title = "Nhãn thực"
        cbar_title = "Tỷ lệ theo nhãn thực (%)"
        basename = "confusion_matrix_binary_vn"
        extra_names = []

    im = render_matrix_ax(ax, CM_B, x_labels, y_labels, x_title, y_title)

    divider = make_axes_locatable(ax)
    cax = divider.append_axes("right", size="8%", pad=0.15)
    cbar = fig.colorbar(im, cax=cax)
    cbar.set_ticks([0, 25, 50, 75, 100])
    cbar.set_ticklabels(["0", "25", "50", "75", "100"])
    cbar.ax.tick_params(labelsize=10, colors=COLOR_DARK_TEXT, length=3)
    cbar.outline.set_edgecolor(COLOR_BORDER)
    cbar.outline.set_linewidth(0.8)
    cbar.set_label(cbar_title, fontsize=11.5, color=COLOR_DARK_TEXT, labelpad=8)

    save_fig_to_all(fig, basename, extra_names=extra_names)


def plot_matplotlib_combined(lang="en"):
    """Generate side-by-side combined figure (a) + (b) with single aligned colorbar."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.0, 4.3), dpi=300,
                                   gridspec_kw={'width_ratios': [5, 3.2]})

    if lang == "en":
        x_title = "Predicted class"
        y_title = "True class"
        cbar_title = "Share of true class (%)"
        title_a = "(a) Five-class GNNMHAv2 ($n = 1,949$)"
        title_b = "(b) Stage-A binary gate ($n = 3,669$)"
        basename = "confusion_matrices_combined_en"
        extra_names = ["confusion_matrices_combined", "confusion_matrices_combined_matplotlib"]
        x_labels_b = CLASSES_B_EN
        y_labels_b = CLASSES_B_Y_EN
    else:
        x_title = "Nhãn dự đoán"
        y_title = "Nhãn thực"
        cbar_title = "Tỷ lệ theo nhãn thực (%)"
        title_a = "(a) Phân loại 5 nhãn canonical ($n = 1,949$)"
        title_b = "(b) Cổng lọc nhị phân Stage-A ($n = 3,669$)"
        basename = "confusion_matrices_combined_vn"
        extra_names = []
        x_labels_b = CLASSES_B_VN
        y_labels_b = CLASSES_B_Y_VN

    render_matrix_ax(ax1, CM_A, CLASSES_A_SHORT, CLASSES_A_FULL, x_title, y_title, title=title_a)
    im2 = render_matrix_ax(ax2, CM_B, x_labels_b, y_labels_b, x_title, y_title, title=title_b)

    divider = make_axes_locatable(ax2)
    cax = divider.append_axes("right", size="7%", pad=0.18)
    cbar = fig.colorbar(im2, cax=cax)
    cbar.set_ticks([0, 25, 50, 75, 100])
    cbar.set_ticklabels(["0", "25", "50", "75", "100"])
    cbar.ax.tick_params(labelsize=10, colors=COLOR_DARK_TEXT, length=3)
    cbar.outline.set_edgecolor(COLOR_BORDER)
    cbar.outline.set_linewidth(0.8)
    cbar.set_label(cbar_title, fontsize=11.5, color=COLOR_DARK_TEXT, labelpad=8)

    save_fig_to_all(fig, basename, extra_names=extra_names)


def update_and_compile_tikz():
    """Update TikZ source files with canonical data and compile if pdflatex is available."""
    pdflatex_bin = shutil.which("pdflatex") or "/Library/TeX/texbin/pdflatex"
    if not Path(pdflatex_bin).exists() or not TIKZ_SRC_DIR.exists():
        print(f"Skipping TikZ compilation (pdflatex: {Path(pdflatex_bin).exists()}, dir: {TIKZ_SRC_DIR.exists()})")
        return

    # Update TikZ TeX files with true canonical data
    tex_a = TIKZ_SRC_DIR / "confusion_matrix_a_five_class.tex"
    if tex_a.exists():
        content_a = r"""\documentclass[border=2pt]{standalone}
\usepackage{tikz}
\usepackage{lmodern}
\renewcommand{\familydefault}{\sfdefault}
\usetikzlibrary{calc}
% Data: canonical test split (n=1,949)
\begin{document}
\begin{tikzpicture}[font=\footnotesize\sffamily]
  \def\cs{0.82}
  % ---------------- (a) five-class ----------------
  \foreach \r/\row in {0/{253,0,1,114,3},1/{2,237,1,119,0},2/{0,0,169,135,0},3/{0,0,4,442,2},4/{0,0,2,122,343}}{
    \foreach \v [count=\c from 0] in \row {
      \pgfmathsetmacro{\shade}{min(100,\v/442*100)}
      \pgfmathsetmacro{\txt}{\v>200 ? 1 : 0}
      \fill[blue!\shade!white] (\c*\cs,-\r*\cs) rectangle ++(\cs,-\cs);
      \draw[white,line width=1pt] (\c*\cs,-\r*\cs) rectangle ++(\cs,-\cs);
      \ifdim\txt pt>0.5pt
        \node[white,font=\footnotesize\bfseries\sffamily] at (\c*\cs+\cs/2,-\r*\cs-\cs/2) {\v};
      \else
        \ifnum\v=0
          \node[gray!60,font=\footnotesize\sffamily] at (\c*\cs+\cs/2,-\r*\cs-\cs/2) {0};
        \else
          \node[black!85,font=\footnotesize\bfseries\sffamily] at (\c*\cs+\cs/2,-\r*\cs-\cs/2) {\v};
        \fi
      \fi
    }
  }
  \foreach \n [count=\i from 0] in {RE,IO,AC,UR,FR}{
    \node[anchor=east] at (-0.05,-\i*\cs-\cs/2) {\n};
    \node[anchor=north] at (\i*\cs+\cs/2,-5*\cs-0.05) {\n};
  }
  \node[rotate=90] at (-0.85,-2.5*\cs) {True class};
  \node at (2.5*\cs,-5*\cs-0.65) {Predicted class};
  \node[font=\footnotesize\bfseries\sffamily] at (2.5*\cs,0.3) {(a) Five-class GNNMHAv2 ($n=1{,}949$)};
\end{tikzpicture}
\end{document}
"""
        tex_a.write_text(content_a)

    for tex_file, base_name in [("confusion_matrices.tex", "confusion_matrices"),
                                 ("confusion_matrix_a_five_class.tex", "confusion_matrix_a_five_class"),
                                 ("confusion_matrix_b_binary_gate.tex", "confusion_matrix_b_binary_gate")]:
        p = TIKZ_SRC_DIR / tex_file
        if p.exists():
            print(f"Compiling {tex_file} with pdflatex...")
            res = subprocess.run([str(pdflatex_bin), "-interaction=nonstopmode", f"-output-directory={TIKZ_SRC_DIR}", str(p)],
                                 capture_output=True, text=True)
            pdf_out = TIKZ_SRC_DIR / f"{base_name}.pdf"
            if pdf_out.exists():
                for d in OUT_DIRS:
                    if d.exists():
                        shutil.copy2(pdf_out, d / f"{base_name}.pdf")


if __name__ == "__main__":
    print("=== Generating High-Resolution Confusion Matrices (Publication Style) ===")
    plot_matplotlib_five_class(lang="en")
    plot_matplotlib_five_class(lang="vn")
    plot_matplotlib_five_class(lang="vn", with_title=True)
    plot_matplotlib_binary_gate(lang="en")
    plot_matplotlib_binary_gate(lang="vn")
    plot_matplotlib_combined(lang="en")
    plot_matplotlib_combined(lang="vn")
    print("\n=== Updating and Compiling TikZ Sources ===")
    update_and_compile_tikz()
    print("\n✅ All confusion matrix figures successfully generated with pixel-perfect reference style!")
