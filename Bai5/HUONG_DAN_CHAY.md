# Bài 5 – Hướng dẫn chạy (Windows / PowerShell)

Giải nén vào thư mục repo của bạn (ví dụ `TH_LTANTT_<MSSV>`), để có `sast-tool/` và `dast-tool/` ngang hàng.

## SAST-TOOL
```powershell
cd sast-tool
pip install -r .\requirements.txt
python -m unittest discover tests                    # Ran 6 tests ... OK
python -m sast_tool.main .\examples\vulnerable_01.py # 8 issues
python -m sast_tool.main .\examples\vulnerable_02.py # 4 issues
```
- Mở `report.sarif` bằng extension "SARIF Viewer" trong VS Code.
- Dùng đường dẫn tương đối như trên (đường dẫn `C:\...` làm parser flake8 bỏ sót lỗi lint).

### Commit (bước GitSecure)
```powershell
cd ..
git add .
git commit -m "[add] sast tool"   # Sẽ bị GitSecure CHẶN -> đúng yêu cầu bài, chụp màn hình
```
Sửa thông tin nhạy cảm ở 2 file:
- `sast-tool/examples/vulnerable_01.py`: đổi giá trị password từ "123456" thành "abc"
- `sast-tool/tests/test_vuln_pattern_matcher.py`: đổi giá trị password từ "secret" thành "abc"

(Hook chỉ chặn chuỗi >= 4 ký tự, còn tool SAST vẫn bắt được "abc" -> unit test vẫn pass.)
```powershell
git add .
git commit -m "[add] sast tool"   # GitSecure: All checks passed.
git push origin main
```

## DAST-TOOL
```powershell
cd dast-tool
pip install -r .\requirements.txt
python -m unittest discover -s tests   # Ran 5 tests ... OK
python .\main.py
python .\app.py                         # chạy Flask, để nguyên cửa sổ này
```
Mở terminal thứ 2 để gọi API:
```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/monitor
Invoke-RestMethod http://127.0.0.1:5000/api/memory
Invoke-RestMethod http://127.0.0.1:5000/api/network
Invoke-RestMethod http://127.0.0.1:5000/api/security
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/sandbox `
  -ContentType "application/json" -Body '{"command":"echo hello"}'
```
Lưu ý: `app.py` đã đổi `host="0.0.0.0"` -> `"127.0.0.1"` vì `/api/sandbox` cho chạy lệnh tùy ý (RCE).
Nếu giảng viên yêu cầu đúng y bản gốc thì đổi lại, nhưng đừng chạy khi đang dùng wifi công cộng.

### Commit
```powershell
cd ..
git add .
git commit -m "[add] dast tool"
git push origin main
```
