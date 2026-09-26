"""
Pipeline Orchestrator — End-to-end PRISM execution.

Orchestrates: Security → Preprocessing → Analysis → Fuzzing → SAI
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Aggregated result from a pipeline run."""

    source_file: str
    masked: bool = False
    contracts_parsed: int = 0
    graphs_built: int = 0
    hotspots: list[dict] = field(default_factory=list)
    llm_findings: list[dict] = field(default_factory=list)
    fuzzing_results: dict = field(default_factory=dict)
    explanations: list[Any] = field(default_factory=list)
    patches: list[Any] = field(default_factory=list)
    final_report: dict = field(default_factory=dict)


class PRISMPipeline:
    """
    End-to-end orchestration of the PRISM analysis pipeline.

    Usage:
        pipeline = PRISMPipeline("configs/default.yaml")
        result = pipeline.run("contracts/Vulnerable.sol")
    """

    def __init__(self, config_path: str = "configs/default.yaml"):
        self.config = self._load_config(config_path)
        self._setup_logging()

    def _load_config(self, path: str) -> dict:
        """Load pipeline configuration from YAML."""
        config_path = Path(path)
        if not config_path.exists():
            logger.warning(f"Config not found at {path}, using defaults")
            return {}
        with open(config_path) as f:
            return yaml.safe_load(f)

    def _setup_logging(self):
        """Configure logging."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def run(self, sol_path: str, output_dir: str = "output") -> PipelineResult:
        """Execute the full PRISM pipeline on a Solidity file."""
        result = PipelineResult(source_file=sol_path)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        source_code = Path(sol_path).read_text()

        # === Stage 1: Security Layer ===
        logger.info("=" * 60)
        logger.info("Stage 1: Security Layer — Data Masking & Privacy Filter")
        logger.info("=" * 60)
        masked_code, mapping_path = self._run_security_layer(source_code, output_path)
        result.masked = True

        # === Stage 2: Preprocessing ===
        logger.info("=" * 60)
        logger.info("Stage 2: Preprocessing — AST, CFG, DFG Extraction")
        logger.info("=" * 60)
        # Pass masked source to preprocessing; fallback to original if Slither requires original symbols
        masked_sol_path = output_path / "masked_source.sol"
        graphs = self._run_preprocessing(str(masked_sol_path) if masked_sol_path.exists() else sol_path, output_path, fallback_path=sol_path)
        result.contracts_parsed = graphs.get("contracts_parsed", 0)
        result.graphs_built = graphs.get("graphs_built", 0)

        # === Stage 3: Dual-Path Analysis ===
        logger.info("=" * 60)
        logger.info("Stage 3: Dual-Path Analysis — GNN + LLM")
        logger.info("=" * 60)
        analysis = self._run_analysis(masked_code, graphs, output_path)
        result.hotspots = analysis.get("hotspots", [])
        result.llm_findings = analysis.get("llm_findings", [])

        # === Stage 4: Fuzzing Engine ===
        logger.info("=" * 60)
        logger.info("Stage 4: Fuzzing Engine — Multi-Feedback Loop")
        logger.info("=" * 60)
        fuzz = self._run_fuzzing(masked_code, result.hotspots, graphs, output_path)
        result.fuzzing_results = fuzz

        # === Stage 5: SAI — Explain + Repair + Report ===
        logger.info("=" * 60)
        logger.info("Stage 5: SAI — Explain, Repair & Report Generation")
        logger.info("=" * 60)
        report = self._run_sai(result, masked_code, output_path, mapping_path)
        result.final_report = report

        logger.info(f"Pipeline complete. Results saved to {output_path}")
        return result

    def _run_security_layer(self, source_code: str, output_path: Path) -> tuple[str, Path]:
        """Run data masking and privacy filtering."""
        from src.security.data_masking import DataMasker
        from src.security.privacy_filter import PrivacyFilter

        sec_config = self.config.get("security", {})

        pf = PrivacyFilter(
            config_path="configs/privacy.yaml",
            sensitivity_level=sec_config.get("privacy_filter", {}).get("sensitivity_level", "high"),
        )
        filter_result = pf.filter(source_code)
        if filter_result.has_redactions:
            logger.info(f"Redacted {filter_result.total_redacted} sensitive patterns")

        masker = DataMasker(config=sec_config.get("masking", {}))
        masked_code = masker.mask_source(filter_result.filtered_code)

        mapping_path = output_path / "mask_mapping.json"
        masker.save_mapping(mapping_path)
        logger.info(f"Masked {len(masker.mapping.original_to_masked)} identifiers")
        (output_path / "masked_source.sol").write_text(masked_code)

        return masked_code, mapping_path

    def _run_preprocessing(self, sol_path: str, output_path: Path, fallback_path: Optional[str] = None) -> dict:
        """Run AST parsing, CFG and DFG construction from masked contract."""
        from src.preprocessing.cfg_builder import CFGBuilder

        # An execution config may pin a local compiler. This avoids an
        # auto-resolver network attempt and makes the compiler provenance
        # explicit. Otherwise retain source-version auto-detection.
        solc = self.config.get("solidity", {}).get("solc")
        if solc:
            logger.info("Using configured solc: %s", solc)
        else:
            try:
                from src.preprocessing.solc_resolver import resolve_and_get_solc

                source = Path(sol_path).read_text()
                version, solc = resolve_and_get_solc(source)
                logger.info(f"Using solc {version}")
            except Exception as e:
                logger.debug(f"Solc auto-detect failed ({e}), using default")
                solc = "solc"

        cfg_builder = CFGBuilder()
        try:
            cfgs = cfg_builder.build_from_slither(sol_path, solc=solc)
            cfg_builder.export_edge_list(output_path / "graphs")
            logger.info(f"Built {len(cfgs)} CFGs from {sol_path}")
            return {"contracts_parsed": 1, "graphs_built": len(cfgs), "cfgs": cfgs}
        except Exception as e:
            logger.warning(f"Preprocessing masked contract failed ({e}). Checking fallback...")
            if fallback_path and fallback_path != sol_path:
                try:
                    cfgs = cfg_builder.build_from_slither(fallback_path, solc=solc)
                    cfg_builder.export_edge_list(output_path / "graphs")
                    logger.info(f"Built {len(cfgs)} CFGs from fallback original {fallback_path}")
                    return {"contracts_parsed": 1, "graphs_built": len(cfgs), "cfgs": cfgs}
                except Exception as e2:
                    logger.error(f"Fallback preprocessing also failed: {e2}")
            return {"contracts_parsed": 0, "graphs_built": 0}

    def _run_analysis(self, masked_code: str, graphs: dict, output_path: Path) -> dict:
        """Run GNN and LLM analysis."""
        results: dict[str, Any] = {"hotspots": [], "llm_findings": []}

        # --- GNN Analysis ---
        gnn_config = self.config.get("gnn", {})
        model_path = gnn_config.get("model_path", "models/gnn_mha/best_model.pt")

        if Path(model_path).exists():
            try:
                results["hotspots"] = self._run_gnn_inference(graphs, model_path, gnn_config)
                logger.info(f"GNN found {len(results['hotspots'])} hotspots")
            except Exception as e:
                logger.warning(f"GNN analysis failed: {e}")
        else:
            logger.warning(f"GNN model not found at {model_path}. Run train_gnn.py first.")

        # --- LLM Analysis ---
        llm_config = self.config.get("llm", {})
        try:
            from src.analysis.llm.auditor import LLMAuditor

            auditor = LLMAuditor(
                provider=llm_config.get("provider", "local"),
                model=llm_config.get("local", {}).get("model", "deepseek-coder-v2:16b"),
                base_url=llm_config.get("local", {}).get("base_url", "http://localhost:11434"),
                allow_mock_fallback=llm_config.get("allow_mock_fallback", True),
            )
            findings = auditor.analyze(masked_code, hotspots=results["hotspots"])
            results["llm_findings"] = findings
            logger.info(f"LLM found {len(findings)} potential issues")
        except Exception as e:
            logger.warning(f"LLM analysis skipped: {e}")
            results["llm_error"] = str(e)

        return results

    def _run_gnn_inference(self, graphs: dict, model_path: str, gnn_config: dict) -> list[dict]:
        """Load trained GNN model and run inference on each function's CFG using a high-precision Cascade filter."""
        import torch

        from src.analysis.gnn.hotspot import VULN_NAMES
        from src.analysis.gnn.model_v2 import GNNMHAv2
        from src.preprocessing.graph_embeddings import graph_to_pyg_data
        from src.preprocessing.graph_embeddings_v2 import graph_to_pyg_data_v2

        cfgs = graphs.get("cfgs", {})
        if not cfgs:
            return []

        device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")

        # ----------------------------------------------------
        # 1. Load the configured binary Stage-A filter.
        # ----------------------------------------------------
        binary_path = gnn_config.get("stage_a_model_path")
        binary_model = None
        if binary_path and Path(binary_path).exists():
            bin_checkpoint = torch.load(binary_path, weights_only=False, map_location="cpu")
            bin_state_dict = (
                bin_checkpoint["model_state_dict"]
                if isinstance(bin_checkpoint, dict) and "model_state_dict" in bin_checkpoint
                else bin_checkpoint
            )

            # Infer architecture
            bin_conv_keys = [k for k in bin_state_dict.keys() if k.startswith("convs.")]
            bin_layers = max(int(k.split(".")[1]) for k in bin_conv_keys) + 1 if bin_conv_keys else 3
            bin_hidden = bin_state_dict["input_proj.weight"].shape[0]
            bin_in_ch = bin_state_dict["input_proj.weight"].shape[1]
            bin_has_ee = "edge_encoder.weight" in bin_state_dict
            bin_edge_dim = bin_state_dict["edge_encoder.weight"].shape[1] if bin_has_ee else 0
            bin_heads = bin_state_dict["convs.0.att"].shape[1] if "convs.0.att" in bin_state_dict else 8

            binary_model = GNNMHAv2(
                in_channels=bin_in_ch,
                hidden_channels=bin_hidden,
                num_classes=2,
                num_heads=bin_heads,
                num_layers=bin_layers,
                edge_dim=bin_edge_dim,
            )
            binary_model.load_state_dict(bin_state_dict)
            binary_model.eval().to(device)
            logger.info("Loaded configured binary Stage-A model")
        elif binary_path:
            logger.warning("Configured Stage-A model does not exist: %s", binary_path)

        # ----------------------------------------------------
        # 2. Load the configured multiclass vulnerability classifier.
        # ----------------------------------------------------
        classifier_path = model_path
        logger.info("Using multiclass GNN classifier from config: %s", classifier_path)

        checkpoint = torch.load(classifier_path, weights_only=False, map_location="cpu")
        state_dict = (
            checkpoint["model_state_dict"]
            if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint
            else checkpoint
        )

        # Infer architecture
        conv_keys = [k for k in state_dict.keys() if k.startswith("convs.")]
        num_layers = max(int(k.split(".")[1]) for k in conv_keys) + 1 if conv_keys else 3
        hidden_dim = state_dict["input_proj.weight"].shape[0]
        model_in_channels = state_dict["input_proj.weight"].shape[1]
        has_edge_encoder = "edge_encoder.weight" in state_dict
        model_edge_dim = state_dict["edge_encoder.weight"].shape[1] if has_edge_encoder else 0
        num_heads = state_dict["convs.0.att"].shape[1] if "convs.0.att" in state_dict else 8

        # Infer classes
        classifier_weight_keys = [k for k in state_dict.keys() if "classifier" in k and "weight" in k]
        last_layer_key = max(classifier_weight_keys, key=lambda k: [int(s) for s in k.split(".") if s.isdigit()] or [0])
        num_classes = state_dict[last_layer_key].shape[0]

        classifier_model = GNNMHAv2(
            in_channels=model_in_channels,
            hidden_channels=hidden_dim,
            num_classes=num_classes,
            num_heads=num_heads,
            num_layers=num_layers,
            edge_dim=model_edge_dim,
        )
        classifier_model.load_state_dict(state_dict)
        classifier_model.eval().to(device)
        logger.info(f"Loaded Classifier: classes={num_classes}, in_channels={model_in_channels}")

        hotspots = []
        threshold = gnn_config.get("threshold", 0.3)

        for func_name, cfg in cfgs.items():
            if cfg.number_of_nodes() < 2:
                continue

            # --- Extract V2 and V1 features ---
            data_v2 = graph_to_pyg_data_v2(cfg=cfg, label=0)
            data_v1 = graph_to_pyg_data(cfg=cfg, label=0, embedding_dim=128)

            # ----------------------------------------------------
            # Stage A: Binary Filtering (Is the function vulnerable?)
            # ----------------------------------------------------
            if binary_model is not None:
                bin_data = data_v2.to(device)
                with torch.no_grad():
                    bin_ea = bin_data.edge_attr if bin_edge_dim > 0 else None
                    bin_logits = binary_model(bin_data.x, bin_data.edge_index, edge_attr=bin_ea)
                    bin_probs = torch.softmax(bin_logits, dim=1)
                    bin_pred = bin_probs.argmax(dim=1).item()
                    bin_conf = bin_probs.max(dim=1).values.item()

                # Class 1 is Safe in binary model. If safe, immediately skip!
                if bin_pred == 1:
                    logger.debug(f"Filtered safe function: {func_name} (conf={bin_conf:.4f})")
                    continue
                logger.info(f"Detected vulnerable hotspot: {func_name} (conf={bin_conf:.4f})")

            # ----------------------------------------------------
            # Stage B: Vulnerability Classification (Which type is it?)
            # ----------------------------------------------------
            data = data_v2 if model_in_channels == 32 else data_v1
            data = data.to(device)

            with torch.no_grad():
                ea = data.edge_attr if model_edge_dim > 0 else None
                logits = classifier_model(data.x, data.edge_index, edge_attr=ea)
                probs = torch.softmax(logits, dim=1)
                pred_class = probs.argmax(dim=1).item()
                confidence = probs.max(dim=1).values.item()

            if confidence < threshold:
                continue

            # Class mapping
            if num_classes == 2:
                if pred_class == 1:
                    continue
                vuln_name = "Vulnerable"
            elif num_classes == 5:
                top5_orig = [0, 1, 2, 3, 5]
                label_names_9 = {
                    0: "reentrancy",
                    1: "integer_overflow",
                    2: "access_control",
                    3: "unchecked_return",
                    4: "denial_of_service",
                    5: "front_running",
                    6: "timestamp_dependence",
                    7: "delegatecall",
                    8: "safe",
                }
                top5_names = {i: label_names_9[c] for i, c in enumerate(top5_orig)}
                vuln_name = top5_names.get(pred_class, f"class_{pred_class}")
            elif num_classes == 9:
                if pred_class == 8:
                    continue
                label_names_9 = {
                    0: "reentrancy",
                    1: "integer_overflow",
                    2: "access_control",
                    3: "unchecked_return",
                    4: "denial_of_service",
                    5: "front_running",
                    6: "timestamp_dependence",
                    7: "delegatecall",
                    8: "safe",
                }
                vuln_name = label_names_9.get(pred_class, f"class_{pred_class}")
            else:
                vuln_name = VULN_NAMES.get(pred_class, f"class_{pred_class}")

            contract_name = func_name.split(".")[0] if "." in func_name else "Unknown"
            short_func = func_name.split(".")[-1] if "." in func_name else func_name

            hotspots.append(
                {
                    "function_name": short_func,
                    "contract_name": contract_name,
                    "full_name": func_name,
                    "risk_score": round(confidence, 4),
                    "vulnerability_hint": vuln_name,
                    "predicted_class": pred_class,
                    "detection_source": "GNN",
                }
            )

        # Sort by risk score (highest first)
        hotspots.sort(key=lambda h: h["risk_score"], reverse=True)
        return hotspots

    def _run_fuzzing(self, masked_code: str, hotspots: list[dict], graphs: dict, output_path: Path) -> dict:
        """Run fuzzing engine with feedback loop."""
        from src.fuzzing.engine import FuzzingEngine
        from src.fuzzing.feedback_loop import FeedbackLoop

        fuzz_config = self.config.get("fuzzing", {})
        engine = FuzzingEngine(config=fuzz_config)

        # Build contract_info from graphs
        cfgs = graphs.get("cfgs", {})
        functions = [{"name": name.split(".")[-1], "parameters": []} for name in cfgs.keys()]
        contract_info = {"functions": functions, "vulnerable_functions": []}

        # Convert hotspots to fuzzing format
        hotspot_dicts = []
        for h in hotspots:
            if isinstance(h, dict):
                hotspot_dicts.append(h)
            else:
                hotspot_dicts.append(
                    {
                        "function_name": getattr(h, "function_name", ""),
                        "risk_score": getattr(h, "risk_score", 0.5),
                        "vulnerability_hint": getattr(h, "vulnerability_hint", ""),
                    }
                )

        # Run feedback loop
        loop = FeedbackLoop(
            max_iterations=fuzz_config.get("max_iterations", 3),
            coverage_target=fuzz_config.get("coverage_target", 90.0),
        )
        loop_result = loop.run(
            source_code=masked_code,
            contract_info=contract_info,
            hotspots=hotspot_dicts,
            fuzzing_engine=engine,
        )

        logger.info(f"Fuzzing: {loop_result.total_crashes} crashes, {loop_result.final_coverage:.1f}% coverage")

        # Save fuzzing results
        fuzz_out = {
            "iterations": loop_result.total_iterations,
            "crashes": loop_result.total_crashes,
            "coverage": loop_result.final_coverage,
            "findings": loop_result.all_findings,
            "converged": loop_result.converged,
        }
        with open(output_path / "fuzzing_results.json", "w") as f:
            json.dump(fuzz_out, f, indent=2, default=str)

        return fuzz_out

    def _run_sai(self, result: PipelineResult, masked_code: str, output_path: Path, mapping_path: Path) -> dict:
        """Run SAI: explain vulnerabilities, generate patches, produce report."""
        from src.sai.explainer import CoTExplainer
        from src.sai.repair import AutoRepair
        from src.sai.report_generator import ReportGenerator

        # Combine all findings
        all_vulns = []
        for h in result.hotspots:
            v = (
                h
                if isinstance(h, dict)
                else {
                    "function_name": h.function_name,
                    "vulnerability_type": h.vulnerability_hint,
                    "risk_score": h.risk_score,
                    "detection_source": "GNN",
                }
            )
            all_vulns.append(v)

        for finding in result.llm_findings:
            if isinstance(finding, dict):
                finding.setdefault("detection_source", "LLM")
                all_vulns.append(finding)

        for finding in result.fuzzing_results.get("findings", []):
            all_vulns.append(
                {
                    "function_name": finding.get("function", ""),
                    "vulnerability_type": finding.get("vulnerability", ""),
                    "risk_score": 0.8,
                    "detection_source": "Fuzzer",
                }
            )

        # Deduplicate by function+type
        seen = set()
        unique_vulns = []
        for v in all_vulns:
            key = (v.get("function_name", ""), v.get("vulnerability_type", ""))
            if key not in seen and key != ("", ""):
                seen.add(key)
                unique_vulns.append(v)

        logger.info(f"Total unique vulnerabilities: {len(unique_vulns)}")

        # Explain
        explainer = CoTExplainer()
        explanations = explainer.explain_all(unique_vulns, masked_code)
        result.explanations = explanations

        # Auto-repair
        repair = AutoRepair()
        patches = repair.generate_all_patches(unique_vulns, masked_code)
        result.patches = patches

        # Generate report
        generator = ReportGenerator(project_name=f"PRISM Audit: {result.source_file}")
        report = generator.generate(
            source_file=result.source_file,
            explanations=explanations,
            patches=patches,
            fuzzing_result=type("R", (), result.fuzzing_results)() if result.fuzzing_results else None,
            gnn_hotspots=result.hotspots,
            llm_findings=result.llm_findings,
            metadata={"contracts_parsed": result.contracts_parsed, "graphs_built": result.graphs_built},
        )

        # Demask report
        try:
            from src.security.demasking import Demasker

            demasker = Demasker(mapping_path=mapping_path)
            report = demasker.demask_report(report)
        except Exception as e:
            logger.warning(f"Demasking failed: {e}")

        # Save reports
        generator.save_json(report, output_path / "prism_report.json")
        generator.save_markdown(report, output_path / "prism_report.md")

        # Save patches
        patches_out = []
        for p in patches:
            patches_out.append(
                {
                    "function": p.function_name,
                    "vulnerability": p.vulnerability_type,
                    "description": p.description,
                    "confidence": p.confidence,
                    "has_diff": p.patched_code != p.original_code,
                }
            )
        with open(output_path / "patches.json", "w") as f:
            json.dump(patches_out, f, indent=2)

        logger.info(f"Report saved to {output_path}")
        return report
