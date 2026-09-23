# Báo cáo kiểm thử bypass GitSecure pre-commit hook

- Dự án: `E:\HK1_26-27\TH_ANTT\Bai1\Lap2`
- Ngày kiểm thử: 23/09/2026
- Người thực hiện: Claude (Cowork), theo yêu cầu của sinh viên chủ sở hữu bài lab
- Dữ liệu dùng trong kiểm thử: **hoàn toàn giả** (ví dụ `FAKE-lab-pass-000`, `FAKEtoken0000000000`, `FAKEvalue123`)

> **Tóm tắt nhanh.** Hook hiện tại chặn đúng tệp mẫu `bad.py` và tệp world-writable trên Linux. Tuy nhiên đã **tái hiện 6 trường hợp tạo được commit chứa nội dung vi phạm chính sách** (kiểm chứng bằng mã thoát `git commit` = 0, commit mới và `git show`). Nghiêm trọng nhất: (1) kiểm tra Bandit **không bao giờ chặn** vì so khớp sai chuỗi `SEVERITY: High`; (2) hook quét **working tree** chứ không quét **staging area**; (3) tệp có tên tiếng Việt bị **bỏ qua hoàn toàn** do Git đặt tên trong dấu ngoặc kép. Trên Windows, kiểm tra world-writable còn **báo nhầm mọi tệp**. Bản vá minh họa (chỉ áp dụng trên bản sao) đã vượt qua toàn bộ 13 ca kiểm thử.

---

## 1. Mục tiêu, phạm vi và môi trường

### 1.1 Mục tiêu

Tìm các điểm yếu có thể khiến dữ liệu hoặc mã không đáp ứng chính sách GitSecure (bí mật cứng trong mã, tệp world-writable, lỗi Bandit mức HIGH) vẫn được commit; phân loại đúng bản chất từng vấn đề; đề xuất và kiểm thử lại biện pháp khắc phục.

### 1.2 Phạm vi và quy tắc đã tuân thủ

| Quy tắc | Cách thực hiện |
|---|---|
| Đọc mã trước khi kết luận | Đã đọc nguyên văn 5 tệp mục tiêu, `.git/config`, `gitsecure.log`, `.venv/pyvenv.cfg` (bản sao chỉ đọc). |
| Không kiểm thử trên repo bài làm | Mọi commit thử nghiệm được tạo trong các repo tạm riêng trong môi trường đám mây của phiên, **ngoài** thư mục Lap2. |
| Không sửa mã gốc / cấu hình toàn cục | Không ghi vào `.githooks/`, `.git/`, không chạy `git config --global`, không reset, không push. |
| Danh tính Git | Chỉ đặt cục bộ trong repo thử nghiệm: `Lab Tester <lab@example.invalid>`. |
| Dữ liệu | Chỉ mật khẩu/token giả. Mẫu Bandit HIGH là hàm băm MD5 vô hại; Bandit phân tích tĩnh, **không thực thi** mã mẫu. |
| Bản vá | Chỉ áp dụng trên bản sao hook trong repo thử nghiệm. Không áp dụng vào bài làm. |
| Báo cáo | Chỉ ghi tệp báo cáo này vào Lap2; **không** `git add`/`commit`. Trước khi ghi, thư mục Lap2 chưa có báo cáo cùng tên nên không cần tạo bản sao lưu. |

### 1.3 Môi trường

**Máy của bạn (chỉ thu thập được bằng cách đọc tệp, không chạy lệnh được trên máy):**

| Thành phần | Giá trị | Nguồn |
|---|---|---|
| Hệ điều hành | Windows (win32, x64) | Thông tin thiết bị của ứng dụng Claude desktop |
| Python (venv) | 3.13.14 | `.venv/pyvenv.cfg` |
| Bandit (venv) | 1.9.4 | thư mục `.venv/Lib/site-packages/bandit-1.9.4.dist-info` |
| `core.hooksPath` | `.githooks` (cấu hình **cục bộ** trong `.git/config`) | `.git/config` |
| `core.filemode` / `core.ignorecase` / `core.symlinks` | `false` / `true` / `false` | `.git/config` |
| Phiên bản Git | **Chưa xác định** – phiên này không có shell trên máy Windows | — |
| Lịch sử repo | 1 commit `7bf2ac7` "Set up GitSecure pre-commit hook" trên `main` | `.git/logs/HEAD` |

**Môi trường kiểm thử (đám mây, Linux):** Linux 6.18 x86_64, Git 2.43.0, Python 3.11.15, Bandit 1.9.4 (cùng phiên bản với venv của bạn, cài trong venv riêng).

> Khác biệt đáng lưu ý: kiểm thử chạy trên Linux. Các hành vi đặc thù Windows (GS-09) được xác nhận bằng mã nguồn CPython và nhật ký `gitsecure.log` của bạn, **chưa chạy lại trên Windows**.

**Lệnh để bạn tự ghi nhận môi trường (chạy trong thư mục Lap2):**

PowerShell:
```powershell
git --version
git config --show-origin --get core.hooksPath
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\bandit.exe --version
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture
```

Git Bash (trên Windows):
```bash
git --version
git config --show-origin --get core.hooksPath
./.venv/Scripts/python.exe --version
./.venv/Scripts/bandit.exe --version
uname -a; cmd //c ver
```

Linux / WSL (venv tạo trên Linux có thư mục `bin/` thay vì `Scripts/`):
```bash
git --version
git config --show-origin --get core.hooksPath
python3 --version; bandit --version
uname -a; cat /etc/os-release
```

---

## 2. Tóm tắt cơ chế hoạt động của hook

Tệp `.githooks/pre-commit` (67 dòng, Python, shebang `#!/usr/bin/env python`). Git chạy hook tại **thư mục gốc của working tree** (theo tài liệu githooks), nên các đường dẫn tương đối trong hook được tính từ gốc repo.

| Bước | Dòng | Kiểm tra gì | Dữ liệu lấy ở đâu | Chặn khi |
|---|---|---|---|---|
| 1. Lấy danh sách tệp | 47 | `git diff --cached --name-only` | Danh sách tên tệp trong index, **có trích dẫn** theo `core.quotePath` | — |
| 2. Lọc tệp | 49 | `os.path.isfile(file)` | **Working tree** | Không tồn tại trên đĩa ⇒ `continue` (bỏ qua) |
| 3. Quét bí mật | 18–27 | 5 regex, `re.IGNORECASE`, dừng ở mẫu khớp đầu tiên | Nội dung đọc từ **working tree**, `errors="ignore"`, bảng mã mặc định của hệ thống | Có mẫu khớp. **Ngoại lệ ⇒ `return None` (cho qua)** |
| 4. Quyền tệp | 29–33 | Bit `S_IWOTH` từ `os.stat` | **Working tree** | Bit được bật |
| 5. Bandit | 35–43 | `bandit -r .` | **Toàn bộ thư mục làm việc**, gồm cả tệp chưa track và `.venv` | stdout chứa chuỗi `"SEVERITY: High"`; hoặc không tìm thấy lệnh `bandit` |
| 6. Kết luận | 57–64 | In kết quả, ghi `gitsecure.log` (chỉ khi chặn), `exit(1)` | — | Có ít nhất 1 phát hiện |

Các tệp cấu hình liên quan:

- `.gitignore`: bỏ qua `.venv/`, `__pycache__/`, `*.pyc`, `gitsecure.log`, `.env`. Đây là cơ chế **tránh vô tình thêm tệp**, không phải kiểm soát truy cập.
- `.gitattributes`: `.githooks/pre-commit text eol=lf`. Đây là thiết lập đúng, giúp shebang không bị hỏng bởi CRLF khi checkout trên Windows.
- `requirements.txt`: `bandit` **không ghim phiên bản**.
- `pre-commit-hook-test/bad.py`: `password = "123456"`, dữ liệu mẫu giả. Regex dòng 9 bắt được; Bandit xếp loại B105 mức **LOW**.
- `gitsecure.log` hiện có: 4 dòng JSON (từ một phiên bản hook trước) và 2 dòng văn bản từ hook hiện tại, trong đó có dòng `File pre-commit-hook-test/bad.py is world-writable!` do chạy trên Windows (xem GS-09).

---

## 3. Bảng tổng hợp phát hiện

Thang mức độ trong phạm vi bài lab: **Cao** = một kiểm soát chính bị vô hiệu hoặc nội dung vi phạm lọt vào commit qua thao tác bình thường; **Trung bình** = cần điều kiện cụ thể hoặc ảnh hưởng tính khả dụng của hook; **Thấp** = ảnh hưởng vận hành/nhật ký, không trực tiếp cho phép commit vi phạm.

| ID | Tên | Loại | Trạng thái | Mức |
|---|---|---|---|---|
| GS-01 | Kiểm tra Bandit không bao giờ kích hoạt (sai chuỗi `SEVERITY: High`) | Lỗi triển khai | **Đã tái hiện** (T1) | Cao |
| GS-02 | Quét working tree thay vì staging area | Lỗi triển khai | **Đã tái hiện** (T2) | Cao |
| GS-03 | Tệp đã stage nhưng bị xóa khỏi working tree bị bỏ qua | Lỗi triển khai | **Đã tái hiện** (T3) | Trung bình |
| GS-04 | Tên tệp không phải ASCII (tiếng Việt) bị bỏ qua do `core.quotePath` | Lỗi triển khai | **Đã tái hiện** (T4) | Cao |
| GS-05 | Regex chỉ phủ cú pháp `key = "value"` | Giới hạn phương pháp regex | **Đã tái hiện** (T5a, T5b) | Trung bình |
| GS-06 | Ngoại lệ/giải mã khi đọc tệp dẫn tới cho qua (fail-open) | Lỗi triển khai | Xác nhận bằng đọc mã | Trung bình |
| GS-07 | Bỏ qua lỗi phân tích, mã trả về và stderr của Bandit | Lỗi triển khai | **Đã tái hiện** (T7) | Trung bình |
| GS-08 | Bandit quét toàn bộ thư mục gồm `.venv`: chậm, nhiễu, sai phạm vi | Lỗi triển khai / vận hành | Mô phỏng + đọc mã | Trung bình |
| GS-09 | Kiểm tra world-writable báo nhầm mọi tệp trên Windows | Cảnh báo giả / lỗi vận hành | Xác nhận bằng mã nguồn CPython + nhật ký của bạn | Trung bình |
| GS-10 | Nhật ký thiếu bền vững (lỗi ghi, mã hóa, chỉ ghi khi chặn) | Lỗi vận hành | T8 tái hiện (vẫn chặn, không phải bypass) | Thấp |
| GS-11 | Hook phía client có thể bị bỏ qua hoặc không được cài | Giới hạn thiết kế của Git hook | `--no-verify` tái hiện (T9); clone không mang `core.hooksPath` đã kiểm chứng | Trung bình |
| GS-12 | Chỉ chặn HIGH; Bandit tôn trọng `# nosec` | Quyết định chính sách | Xác nhận bằng đọc mã + tài liệu | Thấp |
| GS-13 | `requirements.txt` không ghim phiên bản; phạm vi `.gitignore` hẹp | Cấu hình / chuỗi cung ứng | Xác nhận bằng đọc mã | Thấp |

**Số bypass đã tái hiện (commit chứa nội dung vi phạm được tạo thật):** 6 phát hiện: GS-01, 02, 03, 04, 05, 07. Ngoài ra GS-11 (`--no-verify`) cũng tạo được commit, nhưng đó là **hành vi được Git tài liệu hóa**, không phải lỗi của hook hay lỗ hổng của Git.

---

## 4. Phân tích chi tiết

Quy trình chung cho mọi ca kiểm thử (Linux/Git Bash), dùng script ở Phụ lục A:

```bash
T=$(mktemp -d); cd "$T"
git init -q -b main
git config user.name "Lab Tester"; git config user.email "lab@example.invalid"
mkdir .githooks && cp /path/to/copy/of/pre-commit .githooks/ && chmod 755 .githooks/pre-commit
git config core.hooksPath .githooks            # cấu hình CỤC BỘ trong repo tạm
git add .githooks/pre-commit && git commit -q -m init
BASE=$(git rev-parse HEAD)
# ... tạo tệp theo từng ca, git add, rồi:
git commit -m "<ca>"; echo "rc=$?"
[ "$(git rev-parse HEAD)" != "$BASE" ] && echo "COMMIT MỚI" && git show HEAD:<tệp>
```

Tiêu chí **bypass đã tái hiện**: `git commit` trả về 0, **và** HEAD đổi sang commit mới, **và** `git show HEAD:<tệp>` chứa chuỗi đánh dấu giả.

---

### GS-01. Kiểm tra Bandit không bao giờ kích hoạt

- **Loại:** Lỗi triển khai
- **Trạng thái:** Đã tái hiện
- **Mức độ:** Cao. Toàn bộ nhánh kiểm soát Bandit bị vô hiệu với mọi mã nguồn, không cần thao tác bất thường.
- **Vị trí:** `.githooks/pre-commit` dòng 37–38
- **Điều kiện tiên quyết:** Bandit 1.9.4 (định dạng đầu ra hiện hành), có tệp `.py` chứa lỗi mức HIGH.
- **Nguyên nhân kỹ thuật:** Bộ định dạng `txt`/`screen` của Bandit in `Severity: High   Confidence: ...` (xem `bandit/formatters/text.py` dòng 88 trong bản 1.9.4). Toán tử `in` của Python phân biệt hoa/thường, nên `"SEVERITY: High" in result.stdout` luôn là `False`. Hook cũng không dùng `-f json`, không đọc `returncode`.

**Các bước tái hiện:**
1. Tạo repo tạm theo quy trình chung.
2. Tạo `weak_hash.py`:
   ```python
   import hashlib

   def fingerprint(data: bytes) -> str:
       return hashlib.md5(data).hexdigest()
   ```
3. `bandit -q weak_hash.py`: xác nhận có B324, `Severity: High`.
4. `git add weak_hash.py && git commit -m "T1 weak hash"; echo rc=$?`
5. `git show HEAD:weak_hash.py`

- **Kết quả mong đợi:** Commit bị chặn với thông báo Bandit HIGH.
- **Kết quả thực tế (bằng chứng):**
  ```
  >> Issue: [B324:hashlib] Use of weak MD5 hash for security. Consider usedforsecurity=False
     Severity: High   Confidence: High
  GitSecure: All checks passed.
  [main f496a9e] T1 weak hash
   1 file changed, 4 insertions(+)
  commit rc=0
  ```
  `git show HEAD:weak_hash.py` hiển thị đúng nội dung có `hashlib.md5`. Kiểm tra trực tiếp trên đầu ra thật của Bandit: `"SEVERITY: High" in out` → `False`; `"Severity: High" in out` → `True`.
- **Khắc phục:** Không nên chỉ đổi chuỗi. Cần chạy `bandit -f json` và đọc trường `issue_severity == "HIGH"` trong `results`, đồng thời xử lý `errors` và `returncode` (GS-07), và **thu hẹp phạm vi quét về tệp đã stage** (GS-08). Nếu chỉ sửa chuỗi mà vẫn quét `.`, mọi commit sẽ bị chặn bởi mã thư viện trong `.venv` (mô phỏng tìm thấy 22 lỗi HIGH trong venv).
  ```python
  res = subprocess.run([exe, "-r", tmp, "-f", "json", "-q"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
  report = json.loads(res.stdout)
  high = [r for r in report["results"] if r["issue_severity"] == "HIGH"]
  ```
- **Kiểm thử lại:** Lặp lại T1 với bản vá: `rc=1`, không có commit mới, thông báo `Bandit HIGH B324 in weak_hash.py:4` (đã chạy, xem mục 6).
- **Giới hạn còn lại:** Bandit là phân tích tĩnh dựa trên luật, có âm tính giả và dương tính giả; `# nosec` vẫn có hiệu lực (GS-12).

---

### GS-02. Quét working tree thay vì staging area

- **Loại:** Lỗi triển khai
- **Trạng thái:** Đã tái hiện
- **Mức độ:** Cao. Nội dung đi vào commit là nội dung trong index. Quy trình `git add` rồi tiếp tục sửa tệp, hoặc `git add -p`, là thao tác bình thường, nên sự lệch nhau có thể xảy ra vô tình.
- **Vị trí:** dòng 20 (`open(file_path)`), 30 (`os.stat`), 37 (`bandit -r .`), 49 (`os.path.isfile`)
- **Điều kiện tiên quyết:** Tệp đã được `git add`, sau đó working tree bị sửa nhưng không stage lại.
- **Nguyên nhân kỹ thuật:** `git diff --cached` chỉ cung cấp **tên** tệp. Hook đọc nội dung từ đĩa (working tree) thay vì đọc blob trong index (`git cat-file blob :<path>` hoặc `git show :<path>`).

**Các bước tái hiện:**
1. Repo tạm theo quy trình chung.
2. `printf 'password = "FAKE-lab-pass-000"\n' > settings.py && git add settings.py`
3. Sửa working tree nhưng **không** stage lại: `printf 'import os\npassword = os.environ.get("APP_PASSWORD")\n' > settings.py`
4. So sánh: `git show :settings.py` (index) và `cat settings.py` (working tree).
5. `git commit -m "T2 staged differs"; echo rc=$?; git show HEAD:settings.py`
6. Ca đối chứng T0: cùng nội dung giả ở cả index và working tree.

- **Kết quả mong đợi:** Bị chặn vì nội dung sắp commit chứa mật khẩu giả.
- **Kết quả thực tế:**
  ```
  -- staged:   password = "FAKE-lab-pass-000"
  -- worktree: password = os.environ.get("APP_PASSWORD")
  GitSecure: All checks passed.
  [main ce55696] T2 staged differs
  commit rc=0
  -- committed content:
  password = "FAKE-lab-pass-000"
  ```
  Ca đối chứng T0 bị chặn đúng (`rc=1`, `Sensitive info found in control.py`), chứng tỏ regex bắt được nội dung này; nguyên nhân lọt là do **đọc sai nguồn dữ liệu**.
- **Khắc phục:**
  ```python
  def staged_blob(path):
      return subprocess.run(["git", "cat-file", "blob", f":{path}"],
                            check=True, capture_output=True).stdout
  ```
  Quét `staged_blob(path)`; chạy Bandit trên bản sao các blob `.py` ghi vào thư mục tạm.
- **Kiểm thử lại:** T2 với bản vá: bị chặn `settings.py:1: rule KEY_VALUE`, không có commit mới.
- **Giới hạn còn lại:** Kiểm tra quyền tệp (GS-09) vẫn phải dựa vào working tree vì Git chỉ lưu chế độ `100644`/`100755`, không lưu bit world-writable hay ACL.

---

### GS-03. Tệp đã stage nhưng bị xóa khỏi working tree bị bỏ qua

- **Loại:** Lỗi triển khai (cùng gốc với GS-02)
- **Trạng thái:** Đã tái hiện
- **Mức độ:** Trung bình. Cần thao tác cụ thể (xóa tệp trên đĩa sau khi `git add`), ít xảy ra vô tình hơn GS-02.
- **Vị trí:** dòng 49: `if not os.path.isfile(file): continue`
- **Nguyên nhân kỹ thuật:** Dòng 49 nhằm loại tệp bị xóa khỏi repo, nhưng lại kiểm tra sự tồn tại trên **đĩa**. Tệp trạng thái `AD` (thêm vào index, xóa trên đĩa) vẫn được commit nhưng không được quét.

**Các bước tái hiện:**
1. `printf 'token = "FAKEtoken0000000000"\n' > creds_demo.py && git add creds_demo.py`
2. `rm creds_demo.py` (không dùng `git rm`); `git status --short` hiển thị `AD creds_demo.py`
3. `git commit -m "T3"; echo rc=$?; git show HEAD:creds_demo.py`

- **Kết quả mong đợi:** Bị chặn.
- **Kết quả thực tế:** `GitSecure: All checks passed.`, `[main fa753df] T3 deleted from worktree`, `rc=0`; `git show` in ra `token = "FAKEtoken0000000000"`.
- **Khắc phục:** Dùng `git diff --cached --name-only -z --diff-filter=ACMRT` để chỉ lấy tệp thêm/sửa/đổi tên/đổi kiểu (bỏ `D` một cách tường minh), rồi đọc nội dung từ index như GS-02.
- **Kiểm thử lại:** T3 với bản vá: bị chặn `creds_demo.py:1: rule KEY_VALUE`.
- **Giới hạn còn lại:** Không có giới hạn đáng kể cho trường hợp này.

---

### GS-04. Tên tệp không phải ASCII bị bỏ qua do `core.quotePath`

- **Loại:** Lỗi triển khai
- **Trạng thái:** Đã tái hiện
- **Mức độ:** Cao trong bối cảnh bài lab tiếng Việt. Mọi tệp có dấu trong tên (hoặc chứa khoảng trắng đặc biệt, ký tự điều khiển) bị bỏ qua **toàn bộ** các kiểm tra quét bí mật và quyền, một cách âm thầm và không cần chủ đích.
- **Vị trí:** dòng 47 (`--name-only` không có `-z`), dòng 49 (`isfile` trên chuỗi đã bị trích dẫn)
- **Điều kiện tiên quyết:** `core.quotePath` ở giá trị mặc định (`true`), đúng như repo Lap2 (không đặt trong `.git/config`).
- **Nguyên nhân kỹ thuật:** Theo tài liệu git-config, khi `core.quotePath` bật, Git đặt đường dẫn có ký tự "bất thường" trong ngoặc kép và thoát byte dạng bát phân. Tên `cấu_hình.py` trở thành chuỗi `"c\341\272\245u_h\303\254nh.py"`; `os.path.isfile()` trên chuỗi này trả về `False`, nên dòng 49 `continue`.

**Các bước tái hiện:**
1. `git config --get core.quotePath` (không có ⇒ mặc định `true`)
2. `printf 'password = "FAKE-lab-pass-111"\n' > "cấu_hình.py" && git add "cấu_hình.py"`
3. `git diff --cached --name-only` hiển thị `"c\341\272\245u_h\303\254nh.py"`
4. `git commit -m "T4"; echo rc=$?; git show "HEAD:cấu_hình.py"`

- **Kết quả thực tế:** `GitSecure: All checks passed.`, `[main 38d1de5] T4 unicode filename`, `rc=0`; `git show` in ra `password = "FAKE-lab-pass-111"`.
- **Khắc phục:** Thêm `-z` và tách theo byte NUL (tài liệu git-diff: với `-z`, tên đường dẫn được xuất nguyên văn, không bị trích dẫn):
  ```python
  out = git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
  files = [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]
  ```
  Không khuyến nghị sửa bằng cách đặt `core.quotePath=false` vì cách đó vẫn hỏng với tên tệp chứa ký tự xuống dòng và phụ thuộc cấu hình của từng máy.
- **Kiểm thử lại:** T4 với bản vá: bị chặn `cấu_hình.py:1: rule KEY_VALUE`.
- **Giới hạn còn lại:** Git lưu tên tệp dạng byte; trên Windows, Git for Windows dùng UTF-8. Nếu tên không phải UTF-8, `surrogateescape` giữ nguyên byte để truyền lại cho `git cat-file`.

---

### GS-05. Regex chỉ phủ cú pháp `key = "value"`

- **Loại:** Giới hạn phương pháp regex (một phần do cách viết mẫu hiện tại)
- **Trạng thái:** Đã tái hiện cho định dạng `.env` và YAML; phần còn lại xác nhận bằng đọc mã
- **Mức độ:** Trung bình. Tệp cấu hình là nơi bí mật thường xuất hiện nhất.
- **Vị trí:** dòng 6–12
- **Nguyên nhân kỹ thuật (từ mã):**
  - Bốn mẫu đầu đều yêu cầu dấu `=` **và** giá trị trong dấu nháy, nên không khớp YAML (`password: v`), JSON (`"password": "v"`), hay `.env` không có nháy (`DB_PASSWORD=v`).
  - Từ khóa cố định: `apikey` không khớp `api_key`/`api-key`; không có `passwd`, `pwd`, `private key`.
  - `token` chỉ nhận `[A-Za-z0-9]{10,}`, nên token có ký tự `-`, `_`, `.` không khớp; `secret`/`apikey` giới hạn tập ký tự.
  - Mẫu AWS không có ranh giới từ nên có thể báo nhầm. Hàm chỉ báo mẫu **đầu tiên** khớp, không có số dòng.
  - Giới hạn chung của mọi bộ quét dựa trên mẫu tĩnh: không phát hiện được giá trị được tạo ra lúc chạy hoặc biểu diễn gián tiếp. Phần này **không được kiểm thử có chủ đích** trong báo cáo; cần kết hợp công cụ chuyên dụng và rà soát.

**Các bước tái hiện:**
1. T5a: `printf 'DB_PASSWORD=FAKEvalue123\n' > app.env && git add app.env && git commit -m T5a`
2. T5b: `printf 'database:\n  password: FAKEvalue123\n' > config.yml && git add config.yml && git commit -m T5b`
3. `git show HEAD:<tệp>` cho từng ca.

- **Kết quả thực tế:** Cả hai `rc=0`, tạo commit `003a793` (T5a) và `9233b9e` (T5b), `git show` chứa `FAKEvalue123`.
- **Khắc phục (mức lab):** Mở rộng mẫu cho các phân tách `=`/`:`, có hoặc không có nháy, từ khóa có tiền tố/hậu tố; báo **số dòng**; không ghi giá trị bí mật vào nhật ký; loại trừ lời gọi hàm và giá trị giữ chỗ (`None`, `null`, ...) để giảm cảnh báo giả:
  ```python
  KEYS = r"(?:api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key)"
  VALUE = r"(?P<val>\"[^\"\n]{4,}\"|'[^'\n]{4,}'|[^\s\"'#,;(){}\[\]]{4,}(?=\s|$|[#,;}]))"
  KEY_VALUE = re.compile(r"[\"']?[\w.-]*" + KEYS + r"[\w.-]*[\"']?\s*[:=]\s*" + VALUE, re.I)
  ```
  **Mức nhóm:** dùng công cụ chuyên dụng (gitleaks, detect-secrets) có luật theo nhà cung cấp, entropy và baseline.
- **Kiểm thử lại:** T5a/T5b với bản vá: bị chặn. Ca đối chứng C1 (`password = os.environ.get("APP_PASSWORD")`, `timeout = None`) **vẫn được cho qua**, tức không phát sinh cảnh báo giả với mẫu này.
- **Giới hạn còn lại:** Regex không bao giờ đầy đủ. Vẫn có cảnh báo giả (ví dụ `token_type = "Bearer"`) và âm tính giả (ví dụ chú thích kiểu `password: str = "..."`). Cần cơ chế ngoại lệ có kiểm duyệt.

---

### GS-06. Ngoại lệ và giải mã khi đọc tệp dẫn tới cho qua (fail-open)

- **Loại:** Lỗi triển khai
- **Trạng thái:** Xác nhận bằng đọc mã; **chưa tái hiện** (môi trường kiểm thử chạy quyền root nên khó tạo lỗi đọc tệp một cách tất định)
- **Mức độ:** Trung bình
- **Vị trí:** dòng 19–26, dòng 30
- **Nguyên nhân kỹ thuật:**
  - `except Exception: return None` (dòng 25–26): mọi lỗi đọc (quyền, khóa tệp trên Windows, đường dẫn hỏng) đều bị coi là "không có bí mật", tức **fail-open**.
  - `open(..., "r", errors="ignore")` dùng bảng mã mặc định của hệ thống (trên Windows thường là mã ANSI, trừ khi bật UTF-8 mode) và **âm thầm bỏ byte không giải mã được**. Tệp UTF-16 (ví dụ do PowerShell 5.1 `Out-File` tạo ra) có byte NUL xen giữa các ký tự nên regex ASCII không khớp.
  - Ngược lại, `os.stat` ở dòng 30 không được bọc `try`, nên lỗi ở đó làm hook văng traceback, trả mã khác 0, và commit **bị chặn** (fail-closed ngẫu nhiên). Hành vi không nhất quán.
- **Các bước tái hiện dự kiến (chưa chạy):** trên Linux với người dùng không phải root: stage tệp chứa mật khẩu giả, sau đó `chmod 000` tệp trên working tree rồi commit. Kỳ vọng với hook gốc là commit được tạo (vì `open()` lỗi, bị nuốt).
- **Khắc phục:** Đọc từ index (GS-02) và chuyển mọi lỗi thành phát hiện chặn commit:
  ```python
  try:
      data = staged_blob(path)
  except subprocess.CalledProcessError as exc:
      findings.append(f"{path}: cannot read staged content ({exc})")
  ...
  if b"\0" in data[:8192]:
      findings.append(f"{path}: binary/UTF-16 content cannot be scanned -> review manually")
  ```
  Bọc toàn bộ `main()` trong `try/except Exception` và coi ngoại lệ là phát hiện (fail-closed).
- **Kiểm thử lại:** Chưa có ca kiểm thử riêng. Phần fail-closed được kiểm chứng gián tiếp qua T6 (thiếu Bandit) và T7 (Bandit không phân tích được).
- **Giới hạn còn lại:** Chặn mọi tệp nhị phân là chính sách chặt. Dự án thật cần danh sách cho phép theo đuôi tệp hoặc thuộc tính `binary` trong `.gitattributes`.

---

### GS-07. Bỏ qua lỗi phân tích, mã trả về và stderr của Bandit

- **Loại:** Lỗi triển khai
- **Trạng thái:** Đã tái hiện
- **Mức độ:** Trung bình
- **Vị trí:** dòng 37–43
- **Nguyên nhân kỹ thuật:** Hook chỉ tìm chuỗi trong stdout. Khi Bandit không phân tích được một tệp (lỗi cú pháp, lỗi mã hóa), Bandit ghi lỗi và bỏ qua tệp đó, còn hook coi như đạt. Mã trả về và stderr không được kiểm tra. Ghi nhận tích cực: khi **không có** lệnh `bandit`, `FileNotFoundError` được bắt và commit **bị chặn** (T6 xác nhận hành vi fail-closed đúng).

**Các bước tái hiện:**
1. `printf 'def broken(:\n    pass\n' > broken.py && git add broken.py`
2. `git commit -m T7; echo rc=$?; git show HEAD:broken.py`

- **Kết quả thực tế:** hook gốc `rc=0`, commit `1ce3d10` chứa `broken.py` (Bandit không phân tích được tệp này).
- **Khắc phục:** Dùng `-f json`; coi mọi phần tử trong `errors` là phát hiện; coi `returncode` ngoài `{0, 1}` hoặc stdout không phải JSON là lỗi, và chặn.
- **Kiểm thử lại:** Bản vá: `Bandit cannot analyse broken.py: syntax error while parsing AST from file`, bị chặn.
- **Giới hạn còn lại:** Đây là lựa chọn chính sách: chặn mã lỗi cú pháp có thể gây phiền cho commit dở dang. Có thể thay bằng cảnh báo cục bộ và bắt buộc ở CI.

---

### GS-08. Bandit quét toàn bộ thư mục, gồm `.venv`

- **Loại:** Lỗi triển khai / vận hành
- **Trạng thái:** Mô phỏng trong môi trường đám mây và xác nhận bằng đọc mã; chưa đo trên máy bạn
- **Mức độ:** Trung bình
- **Vị trí:** dòng 37 `["bandit", "-r", "."]`
- **Nguyên nhân kỹ thuật:**
  - Danh sách loại trừ mặc định của Bandit là `.svn, CVS, .bzr, .hg, .git, __pycache__, .tox, .eggs, *.egg`, **không có `.venv`** (tài liệu man page Bandit, `bandit/core/constants.py`). `.gitignore` không ảnh hưởng tới Bandit.
  - Quét `.` nghĩa là quét working tree và cả tệp chưa track, **không phải** nội dung sắp commit. Tệp chưa track có lỗi có thể chặn commit không liên quan; tệp đã stage nhưng khác working tree không được quét đúng.
- **Bằng chứng mô phỏng** (venv Linux chứa Bandit 1.9.4 và các phụ thuộc, cùng một `app.py` 1 dòng):

  | Lệnh | Thời gian | Số lỗi | Lỗi HIGH | Số dòng mã quét |
  |---|---|---|---|---|
  | `bandit -r .` | 53,4 s | 2394 | 22 | 403.056 |
  | `bandit -r . -x ./.venv` | 0,2 s | 0 | 0 | 1 |

  Venv của bạn (Python 3.13, pip 26.1.2, trên Windows) khác môi trường mô phỏng, nên con số chỉ mang tính minh họa. Hệ quả quan trọng: hiện tại 22 lỗi HIGH này **bị che** bởi GS-01. Nếu chỉ sửa chuỗi so khớp, **mọi commit sẽ bị chặn**.
- **Khắc phục:** Chỉ quét các blob `.py` đã stage, ghi vào thư mục tạm (bản vá, hàm `run_bandit`). Tối thiểu cũng phải có `-x ./.venv`.
- **Kiểm thử lại:** Toàn bộ ma trận với bản vá chạy nhanh vì Bandit chỉ quét tệp được stage; C1 (tệp sạch) được cho qua.
- **Giới hạn còn lại:** Quét từng tệp riêng lẻ không thấy ngữ cảnh liên tệp (Bandit vốn phân tích theo tệp nên ảnh hưởng nhỏ).

---

### GS-09. Kiểm tra world-writable báo nhầm mọi tệp trên Windows

- **Loại:** Cảnh báo giả / lỗi vận hành (không phải bypass)
- **Trạng thái:** Xác nhận bằng mã nguồn CPython và nhật ký của bạn; **chưa chạy lại trên Windows**
- **Mức độ:** Trung bình. Không cho phép commit vi phạm, nhưng khiến hook chặn mọi commit trên Windows, từ đó tạo động cơ dùng `--no-verify` và làm mất toàn bộ bảo vệ.
- **Vị trí:** dòng 29–33
- **Nguyên nhân kỹ thuật:**
  - Hàm `attributes_to_mode()` trong `Python/fileutils.c` (CPython 3.13) gán `0444` nếu tệp có thuộc tính `FILE_ATTRIBUTE_READONLY`, ngược lại gán **`0666`**. Do đó mọi tệp bình thường có `S_IWOTH` bật.
  - Tài liệu `os.chmod` nêu rõ trên Windows chỉ đặt được cờ read-only; mọi bit khác bị bỏ qua.
  - Quyền thật trên Windows nằm ở **ACL (NTFS)**, không ánh xạ sang bit POSIX. Ngoài ra Git chỉ lưu chế độ `100644`/`100755` (và repo này đặt `core.filemode=false`), nên kiểm tra này là **vệ sinh working tree cục bộ**, không kiểm soát nội dung commit.
- **Bằng chứng:** `gitsecure.log` của bạn có dòng `[2026-09-23 18:05:24.384330] File pre-commit-hook-test/bad.py is world-writable!`, sinh ra từ hook hiện tại trên Windows. Trên Linux, T2 và C1 chứng minh cùng mã không báo nhầm tệp `0644`, và C2 (`chmod 666`) bị chặn đúng.
- **Các bước tái hiện dự kiến trên Windows (PowerShell, trong repo tạm ngoài Lap2):**
  ```powershell
  Set-Content -Encoding ascii -Path ok.py -Value 'x = 1'
  git add ok.py; git commit -m "perm test"; "rc=$LASTEXITCODE"
  # Kỳ vọng với hook gốc: "File ok.py is world-writable!", rc=1
  attrib +R ok.py; git commit -m "perm test ro"; "rc=$LASTEXITCODE"
  # Kỳ vọng: vượt qua kiểm tra quyền (st_mode 0o444)
  ```
- **Khắc phục (mức lab):** Chỉ kiểm tra trên POSIX; trên Windows ghi rõ là không áp dụng thay vì kết luận sai:
  ```python
  if os.name == "nt":
      return []   # st_mode trên Windows chỉ phản ánh cờ read-only
  ```
  **Mức nhóm:** nếu chính sách thật sự cần, kiểm tra ACL bằng `icacls <file>` và tìm quyền ghi (`(W)`, `(M)`, `(F)`) cấp cho `Everyone`, `Users` hoặc `Authenticated Users`; hoặc chuyển kiểm tra quyền sang CI chạy Linux.
- **Kiểm thử lại:** Trên Linux: C2 vẫn bị chặn với bản vá. Trên Windows: **chưa kiểm chứng**. Chạy lại các lệnh ở trên, kỳ vọng commit không bị chặn vì lý do quyền.
- **Giới hạn còn lại:** Bản vá mức lab **không kiểm tra quyền trên Windows**. Đây là đánh đổi có chủ ý, cần ghi nhận trong báo cáo lab.

---

### GS-10. Nhật ký thiếu bền vững

- **Loại:** Lỗi vận hành
- **Trạng thái:** T8 đã tái hiện (lỗi ghi); các điểm khác xác nhận bằng đọc mã
- **Mức độ:** Thấp. Không tạo được commit vi phạm; ảnh hưởng khả năng kiểm toán.
- **Vị trí:** dòng 5, 14–16, 39, 61
- **Nguyên nhân kỹ thuật và quan sát:**
  - `open(LOG_FILE, "a")` không bắt lỗi. T8 (tạo thư mục tên `gitsecure.log`) cho kết quả `IsADirectoryError` với traceback; commit **vẫn bị chặn** (`rc=1`), nhưng người dùng thấy lỗi Python thay vì thông báo chính sách.
  - Không chỉ định `encoding`: trên Windows dùng mã ANSI, nên tên tệp tiếng Việt có thể gây `UnicodeEncodeError` khi ghi (**chưa kiểm chứng**).
  - Chỉ ghi khi chặn; không có bản ghi cho lần PASS. Thông báo Bandit bị ghi hai lần (dòng 39 và 61). Thời gian là giờ địa phương, không có múi giờ.
  - Đường dẫn tương đối `gitsecure.log` hoạt động vì Git chạy hook ở gốc working tree, nhưng sẽ ghi sai chỗ nếu chạy hook thủ công từ thư mục khác.
  - **Chèn dòng:** thông điệp chứa tên tệp. Hiện tại tên có ký tự xuống dòng bị Git trích dẫn (và bị bỏ qua theo GS-04) nên chưa ghi được dòng giả vào log. Khi sửa GS-04 bằng `-z`, tên tệp sẽ là nguyên văn, **nên phải lọc ký tự điều khiển** trước khi ghi.
  - Điểm tốt: hook ghi **mẫu regex**, không ghi giá trị bí mật.
- **Khắc phục:** Đường dẫn tuyệt đối từ `git rev-parse --show-toplevel`; `encoding="utf-8"`; JSON Lines; thời gian UTC; lọc `\x00-\x1f`; bắt `OSError` và chỉ cảnh báo, không làm thay đổi quyết định chặn/cho phép; ghi cả PASS và BLOCKED.
- **Kiểm thử lại:** T8 với bản vá: `rc=1`, thông báo `COMMIT BLOCKED ... bad.py:1: rule KEY_VALUE` và `GitSecure WARNING: cannot write log: [Errno 21] Is a directory`.
- **Giới hạn còn lại:** Nhật ký cục bộ có thể bị chính người dùng sửa hoặc xóa, nên không phải bằng chứng kiểm toán tin cậy. Mức nhóm cần nhật ký ở CI/máy chủ.

---

### GS-11. Giới hạn thiết kế của hook phía client

- **Loại:** Giới hạn thiết kế của Git hook chạy trên máy do người dùng kiểm soát. **Không phải lỗ hổng của Git hay của hook.**
- **Trạng thái:** `--no-verify` đã tái hiện (T9); clone không mang `core.hooksPath` đã kiểm chứng; các điểm còn lại xác nhận bằng tài liệu
- **Mức độ:** Trung bình, vì đây là lý do hook **không thể** là kiểm soát bắt buộc duy nhất.
- **Nội dung:**
  1. `git commit -n/--no-verify`: tài liệu git-commit ghi rõ tùy chọn này bỏ qua hook `pre-commit` và `commit-msg`. T9: `rc=0`, commit chứa `bad.py` với cả hook gốc lẫn bản vá, đúng như tài liệu.
  2. `core.hooksPath=.githooks` nằm trong `.git/config`, là cấu hình **cục bộ, không được clone**. Đã kiểm chứng: repo nguồn có `.githooks`, bản clone có thư mục `.githooks` nhưng `git config --get core.hooksPath` trả rỗng, và Git dùng `.git/hooks`. Người clone mới **không có** bảo vệ cho tới khi tự cấu hình.
  3. Người dùng có toàn quyền sửa/xóa `.githooks/pre-commit`, đổi `core.hooksPath`, hoặc chạy trong môi trường thiếu Python/Bandit.
  4. Một số thao tác tạo commit không chạy `pre-commit` (ví dụ `git merge` dùng hook `pre-merge-commit`) — **chưa kiểm chứng** trong báo cáo này.
- **Khắc phục:** Không "vá" được ở phía client. Cần kiểm tra bắt buộc ở CI/máy chủ (xem mục 5.2). Ở mức lab: ghi chú trong README lệnh cài đặt (`git config core.hooksPath .githooks`) và giải thích giới hạn.

---

### GS-12. Chỉ chặn HIGH; Bandit tôn trọng `# nosec`

- **Loại:** Quyết định chính sách
- **Trạng thái:** Xác nhận bằng đọc mã và tài liệu Bandit
- **Mức độ:** Thấp trong phạm vi lab
- **Nội dung:**
  - `bad.py` bị Bandit xếp B105 mức **LOW** (xem dòng JSON trong `gitsecure.log` của bạn), nên chỉ riêng Bandit sẽ không chặn. Tệp này bị chặn nhờ regex. Đây là lựa chọn ngưỡng, không phải lỗi.
  - Theo tài liệu cấu hình Bandit, thêm `# nosec` (hoặc `# nosec B324`) sẽ bỏ qua cảnh báo trên dòng đó. Tùy chọn `--ignore-nosec` buộc Bandit không bỏ qua.
- **Khuyến nghị:** Ghi chính sách rõ ràng trong README (ngưỡng và lý do). Ở mức nhóm, chạy CI với `--ignore-nosec` hoặc yêu cầu người rà soát (CODEOWNERS) duyệt mọi dòng `# nosec` mới; cân nhắc chặn cả MEDIUM có độ tin cậy HIGH.

---

### GS-13. `requirements.txt` không ghim phiên bản; phạm vi `.gitignore`

- **Loại:** Cấu hình / chuỗi cung ứng
- **Trạng thái:** Xác nhận bằng đọc mã
- **Mức độ:** Thấp
- **Nội dung:**
  - `requirements.txt` chỉ có `bandit`. Hành vi hook phụ thuộc định dạng đầu ra của Bandit (chính GS-01 là ví dụ). Nên ghim phiên bản: `bandit==1.9.4`; mức nhóm dùng thêm `--require-hashes`.
  - `.gitignore` chỉ có `.env`, không bao gồm `.env.*`, `*.pem`, `*.key`. Quan trọng hơn, `.gitignore` **không phải kiểm soát truy cập**: `git add -f` vẫn thêm được và tệp đã track thì không bị ảnh hưởng. Bản vá quét mọi tệp đã stage bất kể `.gitignore`.
  - `.gitattributes` (`eol=lf` cho hook) là thiết lập **đúng**. Không nên bỏ.
  - Shebang `#!/usr/bin/env python`: trên Windows (Git Bash) sẽ dùng `python` đầu tiên trong PATH, có thể không phải Python của `.venv`; nếu Bandit không có trong PATH thì commit bị chặn với thông báo cài Bandit (fail-closed, đúng). Bản vá **giữ nguyên** `python` vì trên Windows `python3` có thể trỏ tới trình cài đặt của Microsoft Store.

---

## 5. Biện pháp khắc phục

### 5.1 Mức phù hợp bài thực hành

Thay đổi tối thiểu, dễ giải thích, xử lý GS-01 đến GS-10:

1. Lấy danh sách bằng `git diff --cached --name-only -z --diff-filter=ACMRT` (GS-03, GS-04).
2. Đọc nội dung từ index bằng `git cat-file blob :<path>` (GS-02, GS-06).
3. Fail-closed: mọi lỗi đọc, lỗi Bandit hoặc ngoại lệ không lường trước đều chặn commit (GS-06, GS-07).
4. Bandit: `-f json`, chỉ trên blob `.py` đã stage, xử lý `errors` và `returncode` (GS-01, GS-07, GS-08).
5. Regex mở rộng cho `=`/`:`, có hoặc không có nháy, báo số dòng (GS-05).
6. Bỏ kiểm tra world-writable trên Windows, ghi rõ giới hạn (GS-09).
7. Nhật ký JSON Lines, UTF-8, UTC, lọc ký tự điều khiển, bắt lỗi ghi (GS-10).
8. Ghim `bandit==1.9.4` trong `requirements.txt` (GS-13).

**Mã minh họa đầy đủ** (đã kiểm thử trên bản sao; **không** áp dụng vào bài làm):

```python
#!/usr/bin/env python
"""GitSecure pre-commit (ban va minh hoa - muc bai thuc hanh).

Nguyen tac:
  * Quet DUNG noi dung se commit (staging area / index), khong doc working tree.
  * Fail-closed: khong kiem tra duoc thi chan commit, khong "bo qua cho qua".
  * Bandit chi chay tren file .py da stage, doc ket qua JSON + ma tra ve.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

# Tu khoa nhay cam; cho phep dang  key = "v", key: v, "key": "v", KEY=v
KEYS = r"(?:api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key)"
# Gia tri: chuoi trong nhay, hoac gia tri tran (kieu .env/YAML) ket thuc o cuoi dong/comment.
# Loai tru loi goi ham nhu os.environ.get(...) de giam canh bao gia.
VALUE = r"(?P<val>\"[^\"\n]{4,}\"|'[^'\n]{4,}'|[^\s\"'#,;(){}\[\]]{4,}(?=\s|$|[#,;}]))"
PLACEHOLDERS = {"none", "null", "true", "false"}
SENSITIVE_PATTERNS = [
    ("KEY_VALUE", re.compile(
        r"[\"']?[\w.-]*" + KEYS + r"[\w.-]*[\"']?\s*[:=]\s*" + VALUE,
        re.IGNORECASE)),
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
MAX_BLOB = 5 * 1024 * 1024  # 5 MB


def git(*args):
    """Chay git, tra ve bytes; loi -> CalledProcessError (fail-closed o main)."""
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


REPO_ROOT = git("rev-parse", "--show-toplevel").decode("utf-8").strip()
LOG_FILE = os.path.join(REPO_ROOT, "gitsecure.log")


def safe(text):
    """Chong chen dong/ky tu dieu khien vao nhat ky."""
    return re.sub(r"[\x00-\x1f\x7f]", lambda m: "\\x%02x" % ord(m.group()), str(text))


def log(status, findings):
    entry = {"time": datetime.now(timezone.utc).isoformat(), "status": status,
             "findings": [safe(f) for f in findings]}
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:  # loi ghi log khong duoc lam doi quyet dinh chan/cho phep
        print(f"GitSecure WARNING: cannot write log: {exc}", file=sys.stderr)


def staged_files():
    """Danh sach file them/sua/doi ten trong index, tach bang NUL (-z)."""
    out = git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def staged_blob(path):
    return git("cat-file", "blob", f":{path}")


def scan_sensitive(path, data):
    if b"\0" in data[:8192]:
        return [f"{path}: binary/UTF-16 content cannot be scanned -> review manually"]
    text = data.decode("utf-8", errors="replace")
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule, rx in SENSITIVE_PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            val = (m.groupdict().get("val") or "").strip("\"'").lower()
            if val in PLACEHOLDERS:
                continue
            hits.append(f"{path}:{lineno}: rule {rule}")  # KHONG ghi gia tri bi mat
    return hits


def check_permissions(path):
    """World-writable chi co nghia tren POSIX. Tren Windows st_mode chi phan anh co
    read-only nen khong dung de ket luan; can kiem tra ACL rieng (icacls)."""
    if os.name == "nt":
        return []
    full = os.path.join(REPO_ROOT, path)
    try:
        st = os.lstat(full)
    except FileNotFoundError:
        return []  # da xoa khoi working tree; noi dung van duoc quet tu index
    if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IWOTH:
        return [f"{path}: world-writable (mode {oct(st.st_mode & 0o777)})"]
    return []


def run_bandit(py_blobs):
    if not py_blobs:
        return []
    exe = shutil.which("bandit")
    if exe is None:
        return ["Bandit not found in PATH -> commit blocked (pip install -r requirements.txt)"]
    with tempfile.TemporaryDirectory() as tmp:
        for path, data in py_blobs.items():
            dst = os.path.join(tmp, path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(data)
        res = subprocess.run([exe, "-r", tmp, "-f", "json", "-q"],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        try:
            report = json.loads(res.stdout)
        except ValueError:
            return [f"Bandit failed (rc={res.returncode}): {res.stderr.strip()[:300]}"]
        findings = [f"Bandit cannot analyse {os.path.relpath(e['filename'], tmp)}: {e['reason']}"
                    for e in report.get("errors", [])]
        for r in report.get("results", []):
            if r.get("issue_severity") == "HIGH":
                findings.append(f"Bandit HIGH {r['test_id']} in "
                                f"{os.path.relpath(r['filename'], tmp)}:{r['line_number']}")
        if res.returncode not in (0, 1):
            findings.append(f"Bandit exited with unexpected code {res.returncode}")
        return findings


def main():
    findings = []
    try:
        py_blobs = {}
        for path in staged_files():
            try:
                data = staged_blob(path)
            except subprocess.CalledProcessError as exc:
                findings.append(f"{path}: cannot read staged content ({exc})")
                continue
            if len(data) > MAX_BLOB:
                findings.append(f"{path}: larger than {MAX_BLOB} bytes, not scanned -> review")
                continue
            findings += scan_sensitive(path, data)
            findings += check_permissions(path)
            if path.endswith(".py"):
                py_blobs[path] = data
        findings += run_bandit(py_blobs)
    except Exception as exc:  # fail-closed
        findings.append(f"GitSecure internal error: {type(exc).__name__}: {exc}")

    if findings:
        print("\nCOMMIT BLOCKED by GitSecure:")
        for f in findings:
            print(" -", safe(f))
        log("BLOCKED", findings)
        sys.exit(1)
    print("GitSecure: All checks passed.")
    log("PASSED", [])


if __name__ == "__main__":
    main()
```

Lưu ý khi dùng bản vá trên Windows: tệp phải lưu với kết thúc dòng LF (đã được `.gitattributes` đảm bảo khi checkout) và `bandit` phải có trong PATH (kích hoạt `.venv` trước khi commit).

### 5.2 Mức phù hợp dự án nhóm

| Lớp | Biện pháp | Xử lý |
|---|---|---|
| Máy lập trình viên | Dùng framework `pre-commit` với cấu hình `.pre-commit-config.yaml` ghim phiên bản (gitleaks hoặc detect-secrets, Bandit). Hook chỉ nhận các tệp đã stage. | GS-02..08, GS-13 |
| Quét đúng nội dung | Luôn quét blob trong index (local) hoặc toàn bộ dải commit của PR (`base..head`) ở CI, **gồm mọi commit trung gian**, không chỉ trạng thái cuối. | GS-02, GS-03 |
| Xử lý lỗi | Fail-closed ở CI: công cụ lỗi hoặc thiếu thì job thất bại. Ở máy cá nhân có thể cảnh báo nhưng CI là bắt buộc. | GS-06, GS-07 |
| Ngoại lệ | Baseline/allowlist được commit và duyệt qua CODEOWNERS; `# nosec` phải kèm mã luật và lý do; CI chạy với `--ignore-nosec` để báo cáo. | GS-05, GS-12 |
| Kiểm tra bắt buộc | Branch protection yêu cầu status check thành công trước khi merge; hoặc hook `pre-receive` trên máy chủ Git tự quản; bật secret scanning/push protection của nền tảng nếu có. | GS-11 |
| Phản ứng sự cố | Bí mật đã vào lịch sử thì **coi như bị lộ**: thu hồi và xoay vòng ngay; việc viết lại lịch sử chỉ là bước phụ. | Mọi phát hiện |
| Quyền tệp | Kiểm tra ở CI Linux, hoặc kiểm tra ACL bằng `icacls` trên Windows nếu chính sách yêu cầu. | GS-09 |
| Nhật ký | Nhật ký kết quả quét lưu ở CI/máy chủ, có kiểm soát truy cập; không ghi giá trị bí mật. | GS-10 |

---

## 6. Bảng kết quả kiểm thử trước/sau sửa

Mỗi ca chạy trong một repo tạm mới (script ở Phụ lục A), trên Linux. "Commit mới" = HEAD thay đổi; "Nội dung vi phạm trong commit" = `git show HEAD:<tệp>` chứa chuỗi đánh dấu.

| Ca | Mô tả | Kỳ vọng | Hook gốc: rc / commit mới / nội dung vi phạm trong commit | Bản vá: rc / commit mới | Kết luận |
|---|---|---|---|---|---|
| C0 | `bad.py` mẫu của bài lab | Chặn | 1 / không / — | 1 / không | Cả hai đúng |
| C1 | Tệp sạch (`os.environ.get`, `None`) | Cho qua | 0 / có (`799b58a`) | 0 / có | Không có cảnh báo giả |
| C2 | Tệp `chmod 666` (Linux) | Chặn | 1 / không / — | 1 / không | Cả hai đúng |
| T1 | Bandit HIGH (B324, MD5) | Chặn | **0 / có (`ffc7ee9`) / có** | 1 / không | GS-01 đã sửa |
| T2 | Index khác working tree | Chặn | **0 / có (`dd9b415`) / có** | 1 / không | GS-02 đã sửa |
| T3 | Stage rồi xóa khỏi working tree | Chặn | **0 / có (`5bffada`) / có** | 1 / không | GS-03 đã sửa |
| T4 | Tên tệp `cấu_hình.py` | Chặn | **0 / có (`3732efb`) / có** | 1 / không | GS-04 đã sửa |
| T5a | `.env`: `DB_PASSWORD=...` | Chặn | **0 / có (`003a793`) / có** | 1 / không | GS-05 cải thiện |
| T5b | YAML: `password: ...` | Chặn | **0 / có (`9233b9e`) / có** | 1 / không | GS-05 cải thiện |
| T6 | Không có Bandit trong PATH | Chặn | 1 / không / — | 1 / không | Hook gốc đã fail-closed đúng |
| T7 | `.py` lỗi cú pháp | Chặn | **0 / có (`1ce3d10`) / có** | 1 / không | GS-07 đã sửa |
| T8 | Không ghi được log + có vi phạm | Chặn, thông báo rõ | 1 / không (traceback `IsADirectoryError`) | 1 / không (cảnh báo rõ ràng) | GS-10 cải thiện |
| T9 | `git commit --no-verify` | Cho qua (theo tài liệu Git) | 0 / có / có | 0 / có / có | GS-11: giới hạn thiết kế, cần CI |

Mã băm commit phụ thuộc thời điểm chạy. Mã băm của hook gốc được ghi lại từ lần chạy ma trận; lần chạy thủ công ban đầu cho T1–T4 tạo các commit `f496a9e`, `ce55696`, `fa753df`, `38d1de5` (trích trong mục 4).

**Chưa kiểm chứng:** GS-06 (lỗi đọc tệp), GS-09 trên Windows, ghi log với mã ANSI trên Windows, hành vi `pre-commit` khi `git merge`.

---

## 7. Thứ tự ưu tiên khắc phục

1. **GS-02 + GS-03 + GS-04**: quét đúng nội dung trong index với `-z`. Sửa một lần xử lý cả ba, và là nền cho các sửa đổi khác.
2. **GS-01 + GS-08 + GS-07**: sửa Bandit **cùng lúc** (JSON, chỉ tệp đã stage, xử lý lỗi). Không sửa riêng GS-01, vì sẽ chặn mọi commit do `.venv`.
3. **GS-09**: sửa kiểm tra quyền trên Windows. Hiện hook gần như không dùng được trên máy của bạn, dễ dẫn đến thói quen `--no-verify`.
4. **GS-06**: chuyển sang fail-closed.
5. **GS-05**: mở rộng regex và ghi rõ giới hạn.
6. **GS-10, GS-13, GS-12**: nhật ký, ghim phiên bản, tài liệu hóa chính sách.
7. **GS-11**: ghi rõ trong báo cáo lab rằng hook là lớp hỗ trợ; kiểm soát bắt buộc phải ở CI/máy chủ.

---

## 8. Giới hạn của quá trình kiểm thử

- Không có shell trên máy Windows của bạn: phiên bản Git trên máy **chưa xác định**; không chạy hook trên Windows. Các ca được chạy trên Linux với Git 2.43.0, Python 3.11.15 và Bandit 1.9.4 (cùng phiên bản Bandit, khác phiên bản Python và Git).
- Số liệu GS-08 đo trên venv mô phỏng, không phải `.venv` của bạn.
- Không kiểm thử có chủ đích các kỹ thuật che giấu giá trị bí mật khỏi regex. Phần đó được nêu ở mức giới hạn phương pháp (GS-05).
- Hook là kiểm soát phía client. Mọi kết luận "đã sửa" chỉ áp dụng khi hook được cài và chạy; `--no-verify` vẫn hoạt động (GS-11).
- Bản vá mới được kiểm thử bằng 13 ca trong báo cáo, chưa phải bộ kiểm thử đầy đủ.

## 9. Tài liệu tham khảo

**Git**
- githooks (thư mục làm việc khi chạy hook; `pre-commit`; `--no-verify`; `core.hooksPath`): https://git-scm.com/docs/githooks
- git-commit (`-n`, `--no-verify`): https://git-scm.com/docs/git-commit
- git-diff (`--cached`, `-z`, `--diff-filter`): https://git-scm.com/docs/git-diff
- git-config (`core.hooksPath`, `core.quotePath`, `core.fileMode`): https://git-scm.com/docs/git-config — nguyên văn đã đối chiếu tại https://github.com/git/git/blob/master/Documentation/config/core.adoc
- git-cat-file: https://git-scm.com/docs/git-cat-file
- gitignore: https://git-scm.com/docs/gitignore
- gitattributes: https://git-scm.com/docs/gitattributes

**Python**
- `os.chmod` (trên Windows chỉ đặt được cờ read-only), `os.stat`: https://docs.python.org/3/library/os.html
- `stat` (`S_IWOTH`): https://docs.python.org/3/library/stat.html
- `subprocess.run`: https://docs.python.org/3/library/subprocess.html
- CPython `attributes_to_mode()` (ánh xạ `FILE_ATTRIBUTE_READONLY` → `0444`/`0666`): https://github.com/python/cpython/blob/3.13/Python/fileutils.c

**Bandit**
- Man page (`-f json`, `-x/--exclude` và danh sách loại trừ mặc định, `--ignore-nosec`, `--exit-zero`): https://bandit.readthedocs.io/en/latest/man/bandit.html
- Cấu hình và `# nosec`: https://bandit.readthedocs.io/en/latest/config.html
- Định dạng đầu ra `Severity: ...`: mã nguồn `bandit/formatters/text.py` (bản 1.9.4, dòng 88), https://github.com/PyCQA/bandit

---

## Phụ lục A. Script ma trận kiểm thử (Linux/Git Bash)

Cách dùng: `./run_matrix.sh <đường-dẫn-bản-sao-hook> <nhãn>`. Script tạo repo tạm cho **mỗi** ca, dùng danh tính cục bộ và dữ liệu giả, và **không** chạm vào Lap2. Cần sửa biến `S` (thư mục làm việc tạm), `BANDIT_PATH` (thư mục chứa `bandit`) và đường dẫn tới bản sao `bad.py`.

```bash
#!/usr/bin/env bash
S=/path/to/scratch            # thư mục tạm NGOÀI Lap2
HOOK="$1"; LABEL="$2"; OUT="$S/results_$LABEL.tsv"
BANDIT_PATH="$S/bv/bin"       # venv riêng có bandit==1.9.4
BAD_PY="$S/bad.py"            # bản sao pre-commit-hook-test/bad.py
: > "$OUT"

new_repo() {
  R=$(mktemp -d "$S/lab_${LABEL}_XXXX"); cd "$R" || exit 1
  git init -q -b main; git config user.name "Lab Tester"; git config user.email "lab@example.invalid"
  mkdir .githooks; cp "$HOOK" .githooks/pre-commit; chmod 755 .githooks/pre-commit
  git config core.hooksPath .githooks
  printf '.venv/\n__pycache__/\n*.pyc\ngitsecure.log\n.env\n' > .gitignore
  git add .gitignore .githooks/pre-commit
  PATH="$BANDIT_PATH:$PATH" git commit -q -m init >/dev/null 2>&1 || git commit -q --no-verify -m init
  BASE=$(git rev-parse HEAD)
}

record() {   # record ID EXPECT PATH MARKER [extra git-commit args]
  local id="$1" expect="$2" path="$3" marker="$4"; shift 4
  PATH="${PATHOVR:-$BANDIT_PATH:$PATH}" git commit -m "$id" "$@" > "$S/out_${LABEL}_$id.txt" 2>&1; local rc=$?
  local head; head=$(git rev-parse HEAD); local created=no; [ "$head" != "$BASE" ] && created=yes
  local has=n/a
  if [ -n "$path" ] && [ "$created" = yes ]; then
    git show "HEAD:$path" 2>/dev/null | grep -qF -- "$marker" && has=yes || has=no
  fi
  local verdict=BLOCK; [ "$created" = yes ] && verdict=PASS
  local ok=OK; [ "$verdict" != "$expect" ] && ok=MISMATCH
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$rc" "$created" "${head:0:7}" "$has" "$expect" "$ok" >> "$OUT"
  unset PATHOVR
}

new_repo; mkdir pre-commit-hook-test; cp "$BAD_PY" pre-commit-hook-test/; git add pre-commit-hook-test/bad.py; record C0 BLOCK pre-commit-hook-test/bad.py 123456
new_repo; printf 'import os\n\npassword = os.environ.get("APP_PASSWORD")\ntimeout = None\n' > clean.py; git add clean.py; record C1 PASS clean.py APP_PASSWORD
new_repo; printf 'x = 1\n' > ww.py; chmod 666 ww.py; git add ww.py; record C2 BLOCK ww.py "x = 1"
new_repo; printf 'import hashlib\n\ndef fingerprint(data: bytes) -> str:\n    return hashlib.md5(data).hexdigest()\n' > weak_hash.py; git add weak_hash.py; record T1 BLOCK weak_hash.py md5
new_repo; printf 'password = "FAKE-lab-pass-000"\n' > settings.py; git add settings.py; printf 'import os\npassword = os.environ.get("APP_PASSWORD")\n' > settings.py; record T2 BLOCK settings.py FAKE-lab-pass-000
new_repo; printf 'token = "FAKEtoken0000000000"\n' > creds_demo.py; git add creds_demo.py; rm creds_demo.py; record T3 BLOCK creds_demo.py FAKEtoken0000000000
new_repo; printf 'password = "FAKE-lab-pass-111"\n' > "cấu_hình.py"; git add "cấu_hình.py"; record T4 BLOCK "cấu_hình.py" FAKE-lab-pass-111
new_repo; printf 'DB_PASSWORD=FAKEvalue123\n' > app.env; git add app.env; record T5a BLOCK app.env FAKEvalue123
new_repo; printf 'database:\n  password: FAKEvalue123\n' > config.yml; git add config.yml; record T5b BLOCK config.yml FAKEvalue123
new_repo; printf 'x = 1\n' > ok.py; git add ok.py; PATHOVR="/usr/local/bin:/usr/bin:/bin"; record T6 BLOCK ok.py "x = 1"
new_repo; printf 'def broken(:\n    pass\n' > broken.py; git add broken.py; record T7 BLOCK broken.py broken
new_repo; rm -f gitsecure.log; mkdir gitsecure.log; cp "$BAD_PY" bad.py; git add bad.py; record T8 BLOCK bad.py 123456
new_repo; cp "$BAD_PY" bad.py; git add bad.py; record T9 PASS bad.py 123456 --no-verify
cat "$OUT"
```

(So với lần chạy thực tế, ca T8 ở đây có thêm `rm -f gitsecure.log` vì bản vá đã tạo tệp log khi commit khởi tạo. Kết quả T8 của bản vá trong mục 6 lấy từ một lần chạy riêng có bước này.)

## Phụ lục B. Tái hiện trên Windows (chưa kiểm chứng trên Windows)

PowerShell, trong thư mục tạm **ngoài** Lap2:

```powershell
$T = Join-Path $env:TEMP ("gitsecure-lab-" + (Get-Random)); New-Item -ItemType Directory $T | Out-Null; Set-Location $T
git init -b main
git config user.name "Lab Tester"; git config user.email "lab@example.invalid"
New-Item -ItemType Directory .githooks | Out-Null
Copy-Item "E:\HK1_26-27\TH_ANTT\Bai1\Lap2\.githooks\pre-commit" .githooks\   # bản SAO của hook
git config core.hooksPath .githooks
& "E:\HK1_26-27\TH_ANTT\Bai1\Lap2\.venv\Scripts\Activate.ps1"              # để có bandit trong PATH
# Tệp phải là ASCII/UTF-8: PowerShell 5.1 Out-File mặc định là UTF-16LE
Set-Content -Encoding ascii -Path weak_hash.py -Value "import hashlib","","def fingerprint(data: bytes) -> str:","    return hashlib.md5(data).hexdigest()"
git add weak_hash.py
attrib +R weak_hash.py        # tránh GS-09 che mất GS-01
git commit -m "T1"; "rc=$LASTEXITCODE"; git log --oneline -1; git show HEAD:weak_hash.py
```

Với hook gốc trên Windows, **mọi** ca sẽ bị chặn trước tiên bởi GS-09 trừ khi tệp trong working tree có thuộc tính read-only (`attrib +R`). Đây là lý do cần sửa GS-09 trước khi quan sát các phát hiện khác trên Windows.
