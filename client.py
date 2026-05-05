import socket, threading, os, subprocess, platform
import customtkinter as ctk
from tkinter import filedialog, messagebox
import sounddevice as sd
import soundfile as sf
from crypto_utils import encrypt_data, decrypt_data, derive_key

class ChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(" Secure Chat Pro")
        self.geometry("450x750")
        self.is_recording = False
        self.last_received_file = None
        self.pending_data = {} # لحفظ البيانات المشفرة مؤقتاً

        # --- العناصر العلوية (كما هي في كودك) ---
        self.username = ctk.CTkEntry(self, placeholder_text="Enter Name"); self.username.pack(pady=5)
        self.key_entry = ctk.CTkEntry(self, placeholder_text="Secret Key", show="*"); self.key_entry.pack(pady=5)
        self.connect_btn = ctk.CTkButton(self, text="Connect to Server", command=self.connect); self.connect_btn.pack(pady=5)
        
        self.chat_box = ctk.CTkTextbox(self, state="disabled", height=300); self.chat_box.pack(fill="both", pady=10, padx=10)
        
        self.msg_entry = ctk.CTkEntry(self, placeholder_text="Type message..."); self.msg_entry.pack(fill="x", padx=10, pady=5)
        
        # --- الأزرار (مكانها الأصلي في كودك) ---
        self.btn_frame = ctk.CTkFrame(self)
        self.btn_frame.pack(pady=5)
        ctk.CTkButton(self.btn_frame, text="Send", width=100, command=self.send_message).grid(row=0, column=0, padx=5)
        ctk.CTkButton(self.btn_frame, text="📁 Send File", width=100, command=self.send_file).grid(row=0, column=1, padx=5)
        
        self.record_btn = ctk.CTkButton(self, text="🎤 Record Voice", fg_color="green", command=self.toggle_record)
        self.record_btn.pack(pady=5)
        
        self.open_file_btn = ctk.CTkButton(self, text="📂 Open Received File", fg_color="#E67E22", command=self.open_file)
        self.open_file_btn.pack(pady=5)
        self.play_btn = ctk.CTkButton(self, text="▶️ Play Voice Note", command=self.play_voice)
        self.play_btn.pack(pady=5)

        # --- المربع الأزرق الصغير (طلبك الخاص) ---
        # جعلناه في الأسفل وبحجم صغير ليكون مجرد "منبه" للرسائل المشفرة
        self.enc_label = ctk.CTkLabel(self, text="🔒 Notifications:", text_color="#0F0E0E", font=("Arial", 15))
        self.enc_label.pack(padx=10, anchor="e") # محاذاة لليمين

        self.enc_log = ctk.CTkTextbox(self, height=70, width=220, fg_color="#87CEEB", text_color="#0A0909", font=("Arial", 15))
        self.enc_log.pack(padx=10, pady=(0, 10), anchor="e") # وضعه في الزاوية اليمين تحت
        self.enc_log.tag_config("clickable", foreground="#f60505", underline=True)

    def log(self, text):
        self.chat_box.configure(state="normal")
        self.chat_box.insert("end", text + "\n")
        self.chat_box.configure(state="disabled")
        self.chat_box.see("end")

    def connect(self):
        try:
            self.name = self.username.get()
            self.key = derive_key(self.key_entry.get())
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(('127.0.0.1', 65432))
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.log("✅ System: Connected securely.")
        except: messagebox.showerror("Error", "Server not found!")

    def send_message(self):
        text = self.msg_entry.get()
        if text:
            msg = f"{self.name}: {text}"
            self.sock.send(b"MSG:" + encrypt_data(self.key, msg))
            self.log(f"You: {text}")
            self.msg_entry.delete(0, "end")

    def send_file(self):
        path = filedialog.askopenfilename()
        if path:
            filename = os.path.basename(path)
            with open(path, "rb") as f:
                encrypted = encrypt_data(self.key, f.read())
            self.sock.send(f"FILE:{filename}|".encode() + encrypted)
            self.log(f"📁 Sent File: {filename}")

    def toggle_record(self):
        if not self.is_recording:
            self.is_recording = True
            self.record_btn.configure(text="🛑 Stop & Send", fg_color="red")
            self.audio_data = []
            self.stream = sd.InputStream(samplerate=44100, channels=1, callback=self.audio_callback)
            self.stream.start()
        else:
            self.is_recording = False
            self.record_btn.configure(text="🎤 Record Voice", fg_color="green")
            self.stream.stop()
            sf.write("sent_voice.wav", self.audio_data, 44100)
            with open("sent_voice.wav", "rb") as f:
                encrypted = encrypt_data(self.key, f.read())
            self.sock.send(b"VOICE:" + encrypted)
            self.log("🎤 Voice Note Sent.")

    def audio_callback(self, indata, frames, time, status):
        self.audio_data.extend(indata.copy())

    def play_voice(self):
        if os.path.exists("received_voice.wav"):
            data, fs = sf.read("received_voice.wav")
            sd.play(data, fs); sd.wait()
        else: self.log("⚠️ No voice note to play.")

    def open_file(self):
        if self.last_received_file and os.path.exists(self.last_received_file):
            if platform.system() == "Windows": os.startfile(self.last_received_file)
            else: subprocess.call(["open" if platform.system() == "Darwin" else "xdg-open", self.last_received_file])
        else: messagebox.showinfo("Info", "No files received yet.")

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(1024 * 1024 * 15)
                if not data: break
                
                # حفظ البيانات المشفرة بانتظار الكليك
                d_id = f"id_{len(self.pending_data)}"
                self.pending_data[d_id] = data

                # وضع الإشعار في البوكس الأزرق الصغير تحت يمين
                self.enc_log.configure(state="normal")
                start_idx = self.enc_log.index("end-1c")
                
                # تحويل أول16   بايت لـ Hex لإثبات التشفير
                hex_preview = data.hex()[:16]

                # نص الإشعار حسب نوع الداتا
                if data.startswith(b"MSG:"): label = f"📩 Enc messege : {hex_preview}..."
                elif data.startswith(b"FILE:"): label = f"📁 File: {hex_preview}..."
                elif data.startswith(b"VOICE:"): label = f"🎤 Voice: {hex_preview}..."
                else: label = f"📥 Data: {hex_preview}..."

                # إضافة النص للبوكس مع الربط بالكليك
                self.enc_log.insert("end", f"{label} [Click]\n", d_id)
                self.enc_log.tag_add("clickable", start_idx, f"{start_idx} lineend")
                self.enc_log.tag_bind(d_id, "<Button-1>", lambda e, mid=d_id: self.on_click_decrypt(mid))
                
                self.enc_log.configure(state="disabled")
                self.enc_log.see("end")
            except:
                break

    def on_click_decrypt(self, d_id):
        data = self.pending_data.get(d_id)
        if not data: return
        try:
            # فك التشفير ورفعه للشات فوق
            if data.startswith(b"MSG:"):
                msg = decrypt_data(self.key, data[4:]).decode()
                self.log(msg)
            elif data.startswith(b"FILE:"):
                header, enc_data = data.split(b"|", 1)
                filename = header.decode().split(":")[1]
                self.last_received_file = filename
                with open(filename, "wb") as f:
                    f.write(decrypt_data(self.key, enc_data))
                self.log(f"📁 File Decrypted: {filename}")
            elif data.startswith(b"VOICE:"):
                with open("received_voice.wav", "wb") as f:
                    f.write(decrypt_data(self.key, data[6:]))
                self.log("🎤 Voice Note Decrypted & Ready.")
        except:
            messagebox.showerror("Error", "Decryption failed!")

if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()