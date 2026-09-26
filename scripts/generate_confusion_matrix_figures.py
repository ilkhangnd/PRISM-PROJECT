#!/usr/bin/env python3
"""
Generate Confusion Matrix figures for PRISM NSS 2026:
- (a) Five-class GNNMHAv2 (n = 1,949)
- (b) Stage-A binary gate (n = 3,669)
- Combined figure (a) + (b)

Produces both:
1. LaTeX TikZ-based vector PDF and high-res PNG (matching exact paper aesthetics)
2. Matplotlib-based high-res PNG and PDF
"""

import os
import shutil
import subprocess
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

# Directories
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TIKZ_SRC_DIR = PROJECT_ROOT / "paper" / "figures" / "src"
FIGURES_DIR = PROJECT_ROOT / "paper" / "figures"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# ----------------- Exact Data -----------------
# (a) Five-class GNNMHAv2 (n = 1,949)
CLASSES_A = ["RE", "IO", "AC", "UR", "FR"]
CM_A = np.array([
    [255,   1,   2, 110,   3],
    [  0, 237,   1, 121,   0],
    [  0,   0, 166, 138,   0],
    [  0,   1,   1, 444,   2],
    [  0,   0,   0, 124, 343]
])

# (b) Stage-A binary gate (n = 3,669)
CLASSES_B = ["Vuln.", "Safe"]
CM_B = np.array([
    [2773,  359],
    [  35,  502]
])



def compile_tikz_and_render():
    """Compile LaTeX TikZ source files to PDF and render to high-res PNG."""
    tex_files = [
        ("confusion_matrices.tex", "confusion_matrices"),
        ("confusion_matrix_a_five_class.tex", "confusion_matrix_a_five_class"),
        ("confusion_matrix_b_binary_gate.tex", "confusion_matrix_b_binary_gate"),
    ]

    for tex_name, base_name in tex_files:
        tex_path = TIKZ_SRC_DIR / tex_name
        if not tex_path.exists():
            print(f"Skipping {tex_name} (not found)")
            continue

        print(f"Compiling {tex_name} with pdflatex...")
        cmd = [
            "/Library/TeX/texbin/pdflatex",
            "-interaction=nonstopmode",
            f"-output-directory={TIKZ_SRC_DIR}",
            str(tex_path)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        pdf_src = TIKZ_SRC_DIR / f"{base_name}.pdf"
        if pdf_src.exists():
            # Copy PDF to figures/ and artifacts/
            shutil.copy2(pdf_src, FIGURES_DIR / f"{base_name}.pdf")
            shutil.copy2(pdf_src, ARTIFACTS_DIR / f"{base_name}.pdf")
            print(f"  -> Generated {base_name}.pdf")

            # Render to PNG using qlmanage
            tmp_render_dir = Path("/tmp/cm_render")
            tmp_render_dir.mkdir(exist_ok=True)
            subprocess.run(["qlmanage", "-t", "-s", "2400", "-o", str(tmp_render_dir), str(pdf_src)],
                           capture_output=True)
            rendered_png = tmp_render_dir / f"{base_name}.pdf.png"
            if rendered_png.exists():
                shutil.copy2(rendered_png, FIGURES_DIR / f"{base_name}.png")
                shutil.copy2(rendered_png, ARTIFACTS_DIR / f"{base_name}.png")
                print(f"  -> Generated {base_name}.png from TikZ")
        else:
            print(f"Failed to generate {base_name}.pdf! Error output:\n{res.stdout[-500:]}")


def plot_matplotlib_five_class():
    """Generate standalone Matplotlib version of 5-class confusion matrix."""
    fig, ax = plt.subplots(figsize=(4.2, 4.0), dpi=300)
    plt.rcParams['font.sans-serif'] = 'Helvetica, Arial, DejaVu Sans'
    
    # Custom colormap from white to intense blue matching TikZ blue!shade!white
    cmap = mcolors.LinearSegmentedColormap.from_list("tikz_blue", ["#ffffff", "#0000ff"])
    norm = mcolors.Normalize(vmin=0, vmax=442)

    im = ax.imshow(CM_A, cmap=cmap, norm=norm, origin="upper")

    # Add values
    for r in range(len(CLASSES_A)):
        for c in range(len(CLASSES_A)):
            val = CM_A[r, c]
            txt_color = "white" if val > 250 else "black"
            fontweight = "bold" if val > 250 else "normal"
            ax.text(c, r, f"{val:,}", ha="center", va="center", color=txt_color,
                    fontweight=fontweight, fontsize=11)

    # Grid
    ax.set_xticks(np.arange(-0.5, len(CLASSES_A), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(CLASSES_A), 1), minor=True)
    ax.grid(which="minor", color="#cccccc", linestyle="-", linewidth=1.0)
    ax.tick_params(which="minor", bottom=False, left=False)

    # Labels
    ax.set_xticks(range(len(CLASSES_A)))
    ax.set_xticklabels(CLASSES_A, fontsize=11)
    ax.set_yticks(range(len(CLASSES_A)))
    ax.set_yticklabels(CLASSES_A, fontsize=11)
    ax.set_xlabel("Predicted class", fontsize=11, labelpad=8)
    ax.set_ylabel("True class", fontsize=11, labelpad=8)
    ax.set_title("(a) Five-class GNNMHAv2 ($n = 1,949$)", fontsize=12, fontweight="bold", pad=12)

    # Clean borders
    for spine in ax.spines.values():
        spine.set_edgecolor("#cccccc")
        spine.set_linewidth(1.0)

    fig.tight_layout()
    out_png = FIGURES_DIR / "confusion_matrix_a_matplotlib.png"
    out_pdf = FIGURES_DIR / "confusion_matrix_a_matplotlib.pdf"
    fig.savefig(out_png, dpi=300, bbox_inches="tight")
    fig.savefig(out_pdf, bbox_inches="tight")
    shutil.copy2(out_png, ARTIFACTS_DIR / "confusion_matrix_a_matplotlib.png")
    shutil.copy2(out_pdf, ARTIFACTS_DIR / "confusion_matrix_a_matplotlib.pdf")
    plt.close(fig)
    print("  -> Saved confusion_matrix_a_matplotlib.png/pdf")


def plot_matplotlib_binary_gate():
    """Generate standalone Matplotlib version of Stage-A binary gate confusion matrix."""
    fig, ax = plt.subplots(figsize=(3.5, 3.5), dpi=300)
    plt.rcParams['font.sans-serif'] = 'Helvetica, Arial, DejaVu Sans'

    cmap = mcolors.LinearSegmentedColormap.from_list("tikz_blue", ["#ffffff", "#0000ff"])
    norm = mcolors.Normalize(vmin=0, vmax=2773)

    im = ax.imshow(CM_B, cmap=cmap, norm=norm, origin="upper")

    for r in range(len(CLASSES_B)):
        for c in range(len(CLASSES_B)):
            val = CM_B[r, c]
            txt_color = "white" if val > 1500 else "black"
            fontweight = "bold" if val > 1500 else "normal"
            ax.text(c, r, f"{val:,}", ha="center", va="center", color=txt_color,
                    fontweight=fontweight, fontsize=12)

    ax.set_xticks(np.arange(-0.5, len(CLASSES_B), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(CLASSES_B), 1), minor=True)
    ax.grid(which="minor", color="#cccccc", linestyle="-", linewidth=1.0)
    ax.tick_params(which="minor", bottom=False, left=False)

    ax.set_xticks(range(len(CLASSES_B)))
    ax.set_xticklabels(CLASSES_B, fontsize=11)
    ax.set_yticks(range(len(CLASSES_B)))
    ax.set_yticklabels(CLASSES_B, fontsize=11)
    ax.set_xlabel("Predicted class", fontsize=11, labelpad=8)
    ax.set_ylabel("True class", fontsize=11, labelpad=8)
    ax.set_title("(b) Stage-A binary gate ($n = 3,669$)", fontsize=12, fontweight="bold", pad=12)

    for spine in ax.spines.values():
        spine.set_edgecolor("#cccccc")
        spine.set_linewidth(1.0)

    fig.tight_layout()
    out_png = FIGURES_DIR / "confusion_matrix_b_matplotlib.png"
    out_pdf = FIGURES_DIR / "confusion_matrix_b_matplotlib.pdf"
    fig.savefig(out_png, dpi=300, bbox_inches="tight")
    fig.savefig(out_pdf, bbox_inches="tight")
    shutil.copy2(out_png, ARTIFACTS_DIR / "confusion_matrix_b_matplotlib.png")
    shutil.copy2(out_pdf, ARTIFACTS_DIR / "confusion_matrix_b_matplotlib.pdf")
    plt.close(fig)
    print("  -> Saved confusion_matrix_b_matplotlib.png/pdf")


def plot_matplotlib_combined():
    """Generate combined side-by-side Matplotlib version of both confusion matrices."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.5, 3.8), dpi=300,
                                   gridspec_kw={'width_ratios': [5, 3.5]})
    plt.rcParams['font.sans-serif'] = 'Helvetica, Arial, DejaVu Sans'
    cmap = mcolors.LinearSegmentedColormap.from_list("tikz_blue", ["#ffffff", "#0000ff"])

    # Plot (a)
    norm1 = mcolors.Normalize(vmin=0, vmax=444)
    ax1.imshow(CM_A, cmap=cmap, norm=norm1, origin="upper")
    for r in range(len(CLASSES_A)):
        for c in range(len(CLASSES_A)):
            val = CM_A[r, c]
            txt_color = "white" if val > 250 else "black"
            fontweight = "bold" if val > 250 else "normal"
            ax1.text(c, r, f"{val:,}", ha="center", va="center", color=txt_color,
                     fontweight=fontweight, fontsize=10.5)

    ax1.set_xticks(np.arange(-0.5, len(CLASSES_A), 1), minor=True)
    ax1.set_yticks(np.arange(-0.5, len(CLASSES_A), 1), minor=True)
    ax1.grid(which="minor", color="#cccccc", linestyle="-", linewidth=1.0)
    ax1.tick_params(which="minor", bottom=False, left=False)
    ax1.set_xticks(range(len(CLASSES_A)))
    ax1.set_xticklabels(CLASSES_A, fontsize=11)
    ax1.set_yticks(range(len(CLASSES_A)))
    ax1.set_yticklabels(CLASSES_A, fontsize=11)
    ax1.set_xlabel("Predicted class", fontsize=11, labelpad=6)
    ax1.set_ylabel("True class", fontsize=11, labelpad=6)
    ax1.set_title("(a) Five-class GNNMHAv2 ($n = 1,949$)", fontsize=11.5, fontweight="bold", pad=10)
    for spine in ax1.spines.values():
        spine.set_edgecolor("#cccccc")
        spine.set_linewidth(1.0)

    # Plot (b)
    norm2 = mcolors.Normalize(vmin=0, vmax=2773)
    ax2.imshow(CM_B, cmap=cmap, norm=norm2, origin="upper")
    for r in range(len(CLASSES_B)):
        for c in range(len(CLASSES_B)):
            val = CM_B[r, c]
            txt_color = "white" if val > 1500 else "black"
            fontweight = "bold" if val > 1500 else "normal"
            ax2.text(c, r, f"{val:,}", ha="center", va="center", color=txt_color,
                     fontweight=fontweight, fontsize=11)

    ax2.set_xticks(np.arange(-0.5, len(CLASSES_B), 1), minor=True)
    ax2.set_yticks(np.arange(-0.5, len(CLASSES_B), 1), minor=True)
    ax2.grid(which="minor", color="#cccccc", linestyle="-", linewidth=1.0)
    ax2.tick_params(which="minor", bottom=False, left=False)
    ax2.set_xticks(range(len(CLASSES_B)))
    ax2.set_xticklabels(CLASSES_B, fontsize=11)
    ax2.set_yticks(range(len(CLASSES_B)))
    ax2.set_yticklabels(CLASSES_B, fontsize=11)
    ax2.set_xlabel("Predicted class", fontsize=11, labelpad=6)
    ax2.set_ylabel("True class", fontsize=11, labelpad=6)
    ax2.set_title("(b) Stage-A binary gate ($n = 3,669$)", fontsize=11.5, fontweight="bold", pad=10)
    for spine in ax2.spines.values():
        spine.set_edgecolor("#cccccc")
        spine.set_linewidth(1.0)

    fig.tight_layout()
    out_png = FIGURES_DIR / "confusion_matrices_combined_matplotlib.png"
    out_pdf = FIGURES_DIR / "confusion_matrices_combined_matplotlib.pdf"
    fig.savefig(out_png, dpi=300, bbox_inches="tight")
    fig.savefig(out_pdf, bbox_inches="tight")
    shutil.copy2(out_png, ARTIFACTS_DIR / "confusion_matrices_combined_matplotlib.png")
    shutil.copy2(out_pdf, ARTIFACTS_DIR / "confusion_matrices_combined_matplotlib.pdf")
    plt.close(fig)
    print("  -> Saved confusion_matrices_combined_matplotlib.png/pdf")


if __name__ == "__main__":
    print("=== Generating TikZ PDF & PNG ===")
    compile_tikz_and_render()
    print("\n=== Generating Matplotlib High-Res Figures ===")
    plot_matplotlib_five_class()
    plot_matplotlib_binary_gate()
    plot_matplotlib_combined()
    print("\n✅ All figures successfully generated!")
