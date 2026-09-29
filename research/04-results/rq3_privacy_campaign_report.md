# PRISM RQ3 Real Physical Privacy & Utility Benchmark Report

**Thời gian Thực nghiệm:** 2026-09-26T20:36:52.751859+00:00  
**Môi trường Thực thi:** Tiến trình vật lý cục bộ (`solc 0.8.30`, `Slither 0.11.5`, `DataMasker`, `Demasker`)  
**Tập Dữ liệu Đánh giá:** 57 Hợp đồng Solidity thực tế (286 Định danh tùy biến được làm mờ)

---

## 1. Kết quả Đo lường Quyền Riêng tư & Tính Khả thi Biên dịch

| Chỉ số Đánh giá | Giá trị Thực đo | Phương pháp Đo lường | Ý nghĩa Kỹ thuật / Ranh giới Bảo mật |
| :--- | :---: | :--- | :--- |
| **Tỷ lệ Biên dịch Thành công (CVR)** | **100.0%** (57/57) | Biên dịch qua `solc 0.8.30` trên 57 hợp đồng sau làm mờ | ✅ 100% Hợp đồng biên dịch sạch |
| **Độ Nhất quán Hoàn nguyên (MCR)** | **100.0%** (57/57) | Khôi phục chính xác mã nguồn gốc qua $\mathcal{T}^{-1}$ | ✅ 100% Exact Source Reconstruction (286/286 ID mapped bijectively) |
| **Mô phỏng Phơi nhiễm Từ điển (Dict-Proxy)** | **30.42%** (87/286) | Đối sánh định danh gốc với 32 thuật ngữ DeFi phổ biến | ◐ 30.42% định danh trùng từ điển miền |
| **Tấn công Tần suất Thứ hạng Token (Freq-ILR)** | **89.51%** (256/286) | Tấn công suy luận theo phân phối tần suất token Zipf | ◐ 89.51% định danh bị đoán trúng qua rank |

---

## 2. Bảo toàn Tên Detector Phân tích Tĩnh (Slither Detector Occurrences Retention)

| Chỉ số Phân tích Tĩnh | Mã Gốc ($S_{raw}$) | Mã Làm mờ ($S_{mask}$) | Tỷ lệ Bảo toàn (Retention) |
| :--- | :---: | :---: | :---: |
| **Số lần Xuất hiện Detector-name** | 229 occurrences | 235 occurrences | **100.0%** (229/229) |

> [!NOTE]
> 1. **Khả năng Biên dịch (CVR)**: Toàn bộ 57 hợp đồng đều biên dịch thành công sau khi DataMasker bảo toàn các thành viên EVM built-in (`transfer`, `send`, `balance`), đơn vị literal và comment (**CVR = 100.0%**).
> 2. **Độ nhất quán hoàn nguyên (Mask Consistency Rate - MCR)**: Đạt **100.0%** trên toàn bộ 57/57 hợp đồng và 286/286 định danh tùy biến, chứng minh khả năng tái dựng mã nguồn gốc chính xác $100\%$ qua ánh xạ hai chiều ($\mathcal{T} \leftrightarrow \mathcal{T}^{-1}$).
> 3. **Bảo toàn Tên Detector Slither**: Thực nghiệm đo lường việc bảo toàn các tên detector của Slither (**100.0%**), phản ánh cấu trúc luồng điều khiển và luồng dữ liệu cơ bản không bị phá vỡ; việc đánh giá suy giảm ngữ nghĩa hay utility của LLM là định hướng mở rộng (Gate B).
> 4. **Ranh giới Bảo mật**: Tỷ lệ rò rỉ dưới tấn công tần suất (89.51%) và mô phỏng từ điển (30.42%) là kết quả đo lường thực tế, phản ánh giới hạn khách quan của cơ chế che giấu định danh tĩnh trước các kẻ tấn công có tri thức tiên nghiệm về miền nghiệp vụ.
