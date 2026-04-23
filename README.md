# CyberShield AI

CyberShield AI là đồ án Học máy theo phong cách Start-up bảo mật, tập trung vào bài toán **Phishing Website Detection**. Hệ thống nhận URL thô, tự bóc tách đặc trưng theo schema 30 cột của bộ dữ liệu UCI, dự đoán mức độ rủi ro và giải thích quyết định bằng **SHAP**.

## Điểm nổi bật

- Dùng **UCI Phishing Websites Dataset** làm nguồn dữ liệu học thuật chuẩn.
- Giữ nguyên **30 thuộc tính kiểu UCI** trong cả train-time lẫn run-time.
- Có hàm công khai `extract_features_from_url(url)` và helper `scan_url(url)`.
- So sánh **Logistic Regression, SVM, Random Forest** bằng **Stratified 5-Fold CV**.
- Tinh chỉnh **Random Forest** bằng **GridSearchCV**.
- Xuất báo cáo gồm **Confusion Matrix, Classification Report, ROC-AUC, Feature Importance, SHAP Summary**.
- Có ứng dụng **Streamlit** để demo quét URL trực tiếp.

## Cấu trúc chính

- `cybershield_ai/feature_extraction.py`: bóc tách đặc trưng URL + HTML + WHOIS/DNS/SSL + reputation.
- `cybershield_ai/training_pipeline.py`: pipeline tải dữ liệu, train, đánh giá, dump model.
- `train.py`: CLI huấn luyện.
- `app.py`: giao diện Streamlit.
- `tests/`: unit test và integration test.

## Cài đặt

```bash
python -m pip install -r requirements.txt
```

## Huấn luyện

Chạy đầy đủ theo đúng spec:

```bash
python train.py
```

Chạy nhanh để smoke test:

```bash
python train.py --quick --sample-size 2000
```

Artifact model được lưu tại:

```text
artifacts/models/cybershield_ai_model.joblib
```

Các biểu đồ và báo cáo được lưu tại:

```text
artifacts/reports/
```

## Chạy ứng dụng


python -m streamlit run app.py


```bash
streamlit run app.py
```


## Quy ước nhãn

- Nhãn gốc UCI: `Result ∈ {-1, 1}`
- Trong project này:
  - `1 = phishing`
  - `0 = legitimate`

## Vì sao phải quan tâm Precision và F1-Score?

- **False Positive**: chặn nhầm website hợp lệ, làm giảm trải nghiệm người dùng và giảm niềm tin vào hệ thống.
- **False Negative**: bỏ lọt website lừa đảo, gây nguy cơ mất tài khoản, rò rỉ dữ liệu và thiệt hại tài chính.
- Vì vậy, trong an ninh mạng không thể chỉ nhìn **Accuracy**. **Precision** giúp kiểm soát cảnh báo sai; **F1-Score** cân bằng giữa Precision và Recall để hệ thống vừa cảnh báo đúng vừa không bỏ lọt quá nhiều mối đe dọa.

## Ghi chú học thuật

- Một số đặc trưng lịch sử trong UCI như traffic, PageRank, Google Index được tái hiện bằng **proxy hiện đại / best-effort** vì nguồn gốc ban đầu đã lỗi thời.
- Nếu truy vấn live thất bại, hệ thống sẽ tự động dùng **feature defaults** học từ tập train để vẫn trả kết quả.



🔴 1. URL giả mạo kiểu “giống thật”
Giả mạo ngân hàng
http://secure-vietcombank-login.com
http://vietcombank.verify-account.security-check.net
http://vcb-login-update.info
http://vietcombank.com.user-authenticate.ru
Giả mạo ví điện tử / thanh toán
http://momo-payment-secure.com
http://paypal.verify-user-login.net
http://zalo-pay-support-check.xyz
http://paypal.account-security-update.info
Giả mạo mạng xã hội
http://facebook.account-verify-security.com
http://instagram.login-check-warning.net
http://facebook-security-update.xyz
http://meta-user-authentication.info
🟠 2. URL dùng kỹ thuật đánh lừa (rất hay gặp)
🔹 Dùng subdomain để lừa
http://facebook.com.verify-login.ru
http://paypal.com.security-check.xyz
http://google.com.account-warning.info

👉 Người dùng tưởng:

domain chính là facebook.com
👉 Nhưng thực tế:
domain thật là verify-login.ru
🔹 Dùng dấu @
http://facebook.com@malicious-site.ru/login
http://paypal.com@secure-check.xyz

👉 Trình duyệt sẽ bỏ phần trước @

🔹 Dùng IP thay domain
http://192.168.1.100/login/facebook
http://103.21.244.10/secure-paypal
🔹 URL rất dài (đánh lừa người dùng)
http://secure-login-facebook-account-verify-user-session-update.com/login/index.php?id=123456
🟡 3. URL encode (nâng cao cho ML)
http://%77%77%77.facebook.com.login.verify.ru
http://paypal.com%2Fsecure%2Flogin%2Fupdate
🟢 4. URL hợp lệ (để bạn cân bằng dataset)
https://www.facebook.com
https://www.paypal.com
https://www.vietcombank.com.vn
