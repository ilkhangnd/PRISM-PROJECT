"""
Integration test — Kiểm tra pipeline end-to-end:
.sol → Masking → CFG → DFG → PyG Data → Dataset
"""

import json
from pathlib import Path


class TestPreprocessingPipeline:
    """Test toàn bộ pipeline tiền xử lý trên VulnerableBank.sol."""

    SOL_PATH = "data/raw/VulnerableBank.sol"

    def test_cfg_extraction(self):
        """CFG phải trích xuất được tất cả hàm."""
        from src.preprocessing.cfg_builder import CFGBuilder

        builder = CFGBuilder()
        cfgs = builder.build_from_slither(self.SOL_PATH)

        assert len(cfgs) >= 6, f"Expected >= 6 CFGs, got {len(cfgs)}"

        # Kiểm tra hàm withdraw phải có ít nhất 5 nodes (logic phức tạp)
        withdraw_cfg = cfgs.get("VulnerableBank.withdraw")
        assert withdraw_cfg is not None, "Không tìm thấy CFG cho withdraw()"
        assert withdraw_cfg.number_of_nodes() >= 5

    def test_cfg_export_json(self, tmp_path):
        """CFG phải xuất được ra JSON edge-list."""
        from src.preprocessing.cfg_builder import CFGBuilder

        builder = CFGBuilder()
        builder.build_from_slither(self.SOL_PATH)
        exported = builder.export_edge_list(str(tmp_path / "graphs"))

        assert len(exported) >= 6

        # Kiểm tra nội dung JSON
        for name, path in exported.items():
            with open(path) as f:
                data = json.load(f)
            assert "nodes" in data
            assert "edges" in data
            assert data["num_nodes"] > 0

    def test_dfg_extraction(self):
        """DFG phải trích xuất được data dependency edges."""
        from src.preprocessing.dfg_builder import DFGBuilder

        builder = DFGBuilder()
        dfgs = builder.build_from_file(self.SOL_PATH)

        assert len(dfgs) >= 6

        # withdraw() phải có data dependency edges (balance read → update)
        withdraw_dfg = dfgs.get("VulnerableBank.withdraw")
        assert withdraw_dfg is not None
        assert withdraw_dfg.number_of_nodes() >= 2

    def test_graph_to_pyg_data(self):
        """CFG + DFG phải chuyển được thành PyG Data object."""
        from src.preprocessing.cfg_builder import CFGBuilder
        from src.preprocessing.dfg_builder import DFGBuilder
        from src.preprocessing.graph_embeddings import graph_to_pyg_data

        cfg_builder = CFGBuilder()
        cfgs = cfg_builder.build_from_slither(self.SOL_PATH)

        dfg_builder = DFGBuilder()
        dfgs = dfg_builder.build_from_file(self.SOL_PATH)

        for func_name, cfg in cfgs.items():
            if cfg.number_of_nodes() < 2:
                continue

            dfg = dfgs.get(func_name)
            data = graph_to_pyg_data(cfg=cfg, dfg=dfg, label=0, embedding_dim=128)

            assert data.x is not None, f"Node features missing for {func_name}"
            assert data.edge_index is not None, f"Edge index missing for {func_name}"
            assert data.x.shape[0] == cfg.number_of_nodes()
            assert data.x.shape[1] == 128  # embedding_dim
            assert data.y.item() == 0  # label

    def test_masking_then_cfg(self):
        """Pipeline: Masking → rồi vẫn phải parse được CFG từ file gốc."""
        from src.preprocessing.cfg_builder import CFGBuilder
        from src.security.data_masking import DataMasker

        # Mask source
        source = Path(self.SOL_PATH).read_text()
        masker = DataMasker()
        masked = masker.mask_source(source)

        # Masked source vẫn phải chứa cấu trúc Solidity
        assert "contract" in masked
        assert "function" in masked
        assert "pragma solidity" in masked

        # CFG vẫn phải build được từ file gốc (masking chỉ cho LLM)
        builder = CFGBuilder()
        cfgs = builder.build_from_slither(self.SOL_PATH)
        assert len(cfgs) >= 6


class TestDataset:
    """Test PyG Dataset class."""

    def test_process_single_file(self, tmp_path):
        """Dataset phải xử lý được ít nhất 1 file .sol."""
        from src.preprocessing.dataset import SmartContractDataset

        # Copy 1 file vào thư mục tạm
        raw_dir = tmp_path / "raw"
        raw_dir.mkdir()
        source = Path("data/raw/VulnerableBank.sol").read_text()
        (raw_dir / "VulnerableBank.sol").write_text(source)

        dataset = SmartContractDataset(
            root=str(tmp_path / "processed"),
            raw_dir=str(raw_dir),
        )
        data_list = dataset.process()

        assert len(data_list) >= 4, f"Expected >= 4 graphs, got {len(data_list)}"

        # Kiểm tra mỗi Data object
        for data in data_list:
            assert data.x is not None
            assert data.edge_index is not None
            assert hasattr(data, "contract_name")

    def test_dataset_with_labels(self, tmp_path):
        """Dataset phải gán đúng nhãn từ labels.json."""
        from src.preprocessing.dataset import VULN_LABELS, SmartContractDataset

        raw_dir = tmp_path / "raw"
        raw_dir.mkdir()
        source = Path("data/raw/VulnerableBank.sol").read_text()
        (raw_dir / "VulnerableBank.sol").write_text(source)

        labels_file = tmp_path / "labels.json"
        labels_file.write_text('{"VulnerableBank": "reentrancy"}')

        dataset = SmartContractDataset(
            root=str(tmp_path / "processed"),
            raw_dir=str(raw_dir),
            labels_file=str(labels_file),
        )
        data_list = dataset.process()

        # Tất cả graph từ VulnerableBank phải có label = reentrancy
        for data in data_list:
            assert data.y.item() == VULN_LABELS["reentrancy"]

    def test_dataset_save_and_load(self, tmp_path):
        """Dataset phải lưu và tải lại được."""
        from src.preprocessing.dataset import SmartContractDataset

        raw_dir = tmp_path / "raw"
        raw_dir.mkdir()
        source = Path("data/raw/VulnerableBank.sol").read_text()
        (raw_dir / "VulnerableBank.sol").write_text(source)

        processed_dir = str(tmp_path / "processed")

        # Process and save
        ds1 = SmartContractDataset(root=processed_dir, raw_dir=str(raw_dir))
        data1 = ds1.process()

        # Load from disk
        ds2 = SmartContractDataset(root=processed_dir, raw_dir=str(raw_dir))
        data2 = ds2.load()

        assert len(data1) == len(data2)

    def test_dataset_stats(self, tmp_path):
        """Stats phải trả về thông tin hợp lệ."""
        from src.preprocessing.dataset import SmartContractDataset

        raw_dir = tmp_path / "raw"
        raw_dir.mkdir()
        source = Path("data/raw/VulnerableBank.sol").read_text()
        (raw_dir / "VulnerableBank.sol").write_text(source)

        dataset = SmartContractDataset(root=str(tmp_path / "processed"), raw_dir=str(raw_dir))
        dataset.process()
        stats = dataset.stats()

        assert stats["total_graphs"] >= 4
        assert stats["avg_nodes"] > 0
        assert stats["unique_contracts"] == 1
