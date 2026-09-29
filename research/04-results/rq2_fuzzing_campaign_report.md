# PRISM RQ2 Khảo nghiệm Tính Khả thi Thực thi trên Foundry/EVM (30 Seeds)

**Thời gian Thực nghiệm:** 2026-09-27T15:42:59.368214+00:00  
**Môi trường Thực thi:** Máy ảo EVM cục bộ qua Foundry Forge 1.5.1  
**Cấu hình Thực nghiệm:** 5 Hợp đồng Mục tiêu $\times$ 30 Hạt giống PRNG (101--130) $\times$ 2 Chế độ Kiểm thử = **300 Lượt Thực thi** (10,000 lượt chạy mờ không ràng buộc mỗi seed)

---

## 1. Kết quả Thực thi Kiểm thử trên Foundry Forge (30 Seeds)

| Chế độ Thực thi | Số Bài Test Vượt qua | Thời gian Thực thi Trung bình ($\mu$) | Ghi chú Workload |
| :--- | :---: | :---: | :--- |
| **Targeted Exploit Test** | **150 / 150 (100.0%)** | **190.26 ms** | $1$ invocation / target (tái hiện chuỗi giao dịch khai thác) |
| **Parameterized Invariant Fuzzing** | **150 / 150 (100.0%)** | **202.75 ms** | $10.000$ iterations / seed (kiểm tra bất biến trạng thái) |

---

## 2. Chi tiết Vết Thực thi và Tiêu thụ Gas trên 5 Mục tiêu Canonical

| Hợp đồng Mục tiêu | Dạng Lỗ hổng (Taxonomy) | Exploit Test Gas | Fuzz Test Mean Gas ($\mu$) | Exploit Verification (30/30 seeds) | Fuzz Invariant Runs (30/30 seeds) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `SimpleDAO` | Reentrancy | 77,558 | **50,393.73** | ✅ PASS (30/30) | ✅ 10k runs PASS (30/30) |
| `TokenSale` | Integer Overflow | 39,648 | **36,272.50** | ✅ PASS (30/30) | ✅ 10k runs PASS (30/30) |
| `UnprotectedVault` | Access Control | 48,550 | **42,252.00** | ✅ PASS (30/30) | ✅ 10k runs PASS (30/30) |
| `UncheckedBank` | Unchecked Return Value | 27,202 | **50,029.00** | ✅ PASS (30/30) | ✅ 10k runs PASS (30/30) |
| `TimestampLock` | Timestamp Dependence | 39,827 | **13,148.87** | ✅ PASS (30/30) | ✅ 10k runs PASS (30/30) |

---

## 3. Nhận định Kỹ thuật và Giới hạn Thực nghiệm (Scope Boundaries)
1. **Khảo nghiệm Tính Khả thi Thực thi (Execution Feasibility)**: Báo cáo này xác nhận động cơ kiểm thử động của PRISM thực thi trơn tru trên máy ảo EVM Foundry Forge 1.5.1 qua 30 seeds độc lập mà không gặp lỗi môi trường.
2. **Phân định Taxonomy & Định danh Lỗ hổng**: Taxonomy 5 lớp canonical của PRISM bao gồm SWC-107, SWC-101, SWC-105, SWC-104 và SWC-114 (Timestamp Dependence). Mục tiêu `TimestampLock` được kiểm nghiệm cùng 4 mục tiêu canonical khác, đảm bảo cả 5 mục tiêu khớp 1-1 với 5 lớp taxonomy chính thức của PRISM.
3. **Ranh giới Thực nghiệm**: Script chạy 2 bài test Foundry dựng sẵn (`testGuidedExploit` và `testRandomFuzz`), không gọi GNN/LLM lúc runtime và không đo branch coverage/TTFB thời gian thực.
