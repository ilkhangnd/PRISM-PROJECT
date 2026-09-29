# PRISM RQ4 Khảo nghiệm Tính Khả thi Lọc Cascade & Đối chuẩn Baseline Slither 0.11.5

**Thời gian Thực nghiệm:** 2026-09-27T16:28:34.918769+00:00  
**Môi trường Thực thi:** Tiến trình vật lý cục bộ (`Slither 0.11.5`, `Foundry Forge 1.5.1`)  
**Tập Dữ liệu Đánh giá:** 57 Hợp đồng (27 Mẫu an toàn, 30 Mẫu chứa lỗi) từ nhãn benchmark và mẫu tiêm SolidiFI

---

## 1. Kết quả Đối chuẩn Phân tích Tĩnh Slither 0.11.5 ở Cấp Hợp đồng (Contract-Level)

| Chỉ số Đánh giá | Giá trị Thực đo | Phương pháp Đo lường | Ý nghĩa Đối chuẩn |
| :--- | :---: | :--- | :--- |
| **Tổng số Cảnh báo Heuristic** | **230** | Quét detector thô của Slither 0.11.5 trên 57 hợp đồng | Khối lượng cảnh báo lớn |
| **Contract-level Precision** | **52.63%** | $\text{TP} / (\text{TP} + \text{FP})$ | Độ chính xác thấp do gắn cờ trên toàn bộ mã sạch |
| **Contract-level Recall** | **100.00%** | $\text{TP} / (\text{TP} + \text{FN})$ | ✅ 100% Bao phủ toàn bộ mẫu chứa lỗi |
| **Contract-level Macro F1** | **68.97%** | Trung bình điều hòa giữa Precision và Recall | Chỉ số tham chiếu baseline |
| **Confusion Matrix (Contract-level)** | **TP=30, FP=27, TN=0, FN=0** | Phân loại hợp đồng theo nhãn benchmark ground truth | Đánh giá ở cấp độ file |

---

## 2. Tiến trình Khảo nghiệm Lọc Cảnh báo qua Phân tầng Cascade Routing

| Tầng Phân loại Cascade | Số Cảnh báo Còn lại | Hợp đồng Sạch bị Cảnh báo | Hợp đồng Chứa Lỗi được Giữ | Cơ chế Lọc của Tầng |
| :--- | :---: | :---: | :---: | :--- |
| **Stage 0: Slither Static Analysis (Raw Heuristics)** | **230** | **27/27 (100.0%)** | **30/30 (100.0%)** | Baseline heuristic scan on 57 benchmark contracts; flags 27/27 (100.0%) clean contracts due to style, naming, and dead-code rules. |
| **Stage 1: Taxonomy & Detector Relevance Filtering** | **41** | **6/27 (22.2%)** | **18/30 (60.0%)** | Filters detectors by 5 target vulnerability taxonomy classes (alarms reduced to 41, clean flagged reduced to 6/27). |
| **Stage 2: Contextual Impact & Confidence Verification** | **33** | **6/27 (22.2%)** | **18/30 (60.0%)** | Filters for High/Medium impact and confidence detectors (alarms reduced to 33). |
| **Stage 3: Foundry Dynamic Invariant Replay** | **27** | **0/27 (0.0%)** | **18/30 (60.0%)** | Dynamic EVM execution in Foundry on contracts with test harnesses; refutes all 6 false alarms with mutex locks. |

> [!NOTE]
> 1. **Baseline Slither 0.11.5 (Stage 0)**: Gắn cờ trên 100% hợp đồng mẫu sạch (27/27) do các cảnh báo heuristic (dead code, unused return, style conventions), dẫn đến $\text{FPR} = 100.0\%$ trên mã an toàn.
> 2. **Phân tầng Lọc Stage 1 & Stage 2**: Lọc dựa trên thuộc tính detector và impact/confidence của Slither giúp giảm từ 230 cảnh báo xuống 33 cảnh báo, cắt giảm số hợp đồng an toàn bị gắn cờ từ 27/27 xuống 6/27.
> 3. **Kiểm chứng Động Stage 3 (Foundry Invariant Replay)**: Thực thi vật lý trên EVM kiểm chứng hành vi reentrancy đối với 6 hợp đồng an toàn có modifier khóa mutex `noReentrant()`, xác nhận transaction revert và bảo toàn số dư, từ đó triệt tiêu 100% cảnh báo giả (6/6 mẫu, đưa FPR về 0.0%) trong khi bảo toàn các hợp đồng chứa lỗi.
