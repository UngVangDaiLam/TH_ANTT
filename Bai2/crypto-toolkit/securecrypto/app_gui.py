import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.exceptions import InvalidTag
from securecrypto import aes_utils


def encrypt():
    file = filedialog.askopenfilename()
    if not file:  # bấm Cancel ở hộp chọn file
        return
    pw = password_entry.get()
    if not pw:
        messagebox.showerror("Lỗi", "Nhập mật khẩu trước khi mã hoá")
        return
    key = aes_utils.encrypt_file_aes(file, pw)
    # Label không bôi đen để copy được -> đưa Key vào clipboard, dán vào ô khi giải mã
    root.clipboard_clear()
    root.clipboard_append(key)
    result_label.config(text=f"Key: {key}")
    print(key)                              # in key ra terminal
    password_entry.delete(0, tk.END)        # xoá mật khẩu trong ô
    password_entry.insert(0, key)           # điền sẵn key để giải mã

def decrypt():
    file = filedialog.askopenfilename()
    if not file:
        return
    pw = password_entry.get()
    try:
        out = aes_utils.decrypt_file_aes(file, pw)
    except InvalidTag:
        messagebox.showerror("Lỗi", "Sai Key/mật khẩu hoặc file đã bị sửa")
        return
    result_label.config(text=f"Output: {out}")


root = tk.Tk()
root.title("SecureCrypto GUI")
password_entry = tk.Entry(root, show="*")
password_entry.pack()
tk.Button(root, text="Encrypt", command=encrypt).pack()
tk.Button(root, text="Decrypt", command=decrypt).pack()
result_label = tk.Label(root, text="")
result_label.pack()
root.mainloop()
