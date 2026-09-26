"""
CLI Entry Point — Command-line interface for the PRISM framework.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="PRISM")
def main():
    """PRISM: Privacy-Preserving Automated Pentesting Framework for Smart Contracts."""
    pass


@main.command()
@click.argument("sol_path", type=click.Path(exists=True))
@click.option("--config", "-c", default="configs/default.yaml", help="Pipeline config file")
@click.option("--output", "-o", default="output", help="Output directory")
def run(sol_path: str, config: str, output: str):
    """Run the full PRISM pipeline on a Solidity file."""
    console.print(
        Panel.fit(
            "[bold cyan]PRISM[/bold cyan] — Privacy-Preserving Automated Pentesting Framework",
            border_style="cyan",
        )
    )
    console.print(f"[dim]Input:[/dim]  {sol_path}")
    console.print(f"[dim]Config:[/dim] {config}")
    console.print(f"[dim]Output:[/dim] {output}")
    console.print()

    from src.pipeline import PRISMPipeline

    pipeline = PRISMPipeline(config)
    result = pipeline.run(sol_path, output)

    console.print()
    console.print(
        Panel.fit(
            f"[green]✓ Analysis complete[/green]\n"
            f"  Contracts: {result.contracts_parsed}\n"
            f"  Graphs: {result.graphs_built}\n"
            f"  Hotspots: {len(result.hotspots)}\n"
            f"  Findings: {len(result.llm_findings)}",
            title="Results",
            border_style="green",
        )
    )


@main.command()
@click.argument("sol_path", type=click.Path(exists=True))
@click.option("--config", "-c", default="configs/default.yaml")
def preprocess(sol_path: str, config: str):
    """Run only the preprocessing stage (AST/CFG/DFG extraction)."""
    console.print("[cyan]Running preprocessing...[/cyan]")
    from src.preprocessing.cfg_builder import CFGBuilder

    builder = CFGBuilder()
    cfgs = builder.build_from_slither(sol_path)
    builder.export_edge_list("output/graphs")
    console.print(f"[green]✓ Built {len(cfgs)} CFGs[/green]")


@main.command()
@click.argument("sol_path", type=click.Path(exists=True))
def mask(sol_path: str):
    """Mask a Solidity file (anonymize identifiers)."""
    from pathlib import Path

    from src.security.data_masking import DataMasker

    source = Path(sol_path).read_text()
    masker = DataMasker()
    masked = masker.mask_source(source)

    out_path = Path(sol_path).stem + "_masked.sol"
    Path(out_path).write_text(masked)
    masker.save_mapping(Path("output/mask_mapping.json"))
    console.print(f"[green]✓ Masked file saved to {out_path}[/green]")


if __name__ == "__main__":
    main()
