import cv2
import pytesseract
import re
import numpy as np
import time
import serial
import sqlite3
import threading
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from PIL import Image, ImageTk
from datetime import datetime, timedelta
import hashlib
import logging
import os
import ctypes

# =============================
# Logging yapılandırması
# =============================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# =============================
# Tesseract yolu (sisteme göre ayarla)
# =============================
tesseract_path = os.path.join(os.path.dirname(__file__), "Tesseract-OCR", "tesseract.exe")
pytesseract.pytesseract.tesseract_cmd = tesseract_path

# =============================
# Veritabanı bağlantısı ve tablolar
# =============================
try:
    conn = sqlite3.connect("plates.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS plates
                   (
                       plate
                       TEXT
                       PRIMARY
                       KEY
                   )
                   """)
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS users
                   (
                       username
                       TEXT
                       PRIMARY
                       KEY,
                       password_hash
                       TEXT
                       NOT
                       NULL
                   )
                   """)
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS log_dates
                   (
                       date
                       TEXT
                       PRIMARY
                       KEY
                   )
                   """)

    conn.commit()
    logging.info("Veritabanı tabloları oluşturuldu veya kontrol edildi.")

    # FIX: plates.db dosyasını gizli yap
    db_path = os.path.abspath("plates.db")
    FILE_ATTRIBUTE_HIDDEN = 0x02
    ret = ctypes.windll.kernel32.SetFileAttributesW(db_path, FILE_ATTRIBUTE_HIDDEN)
    if ret:
        logging.info(f"Veritabanı dosyası gizlendi: {db_path}")
    else:
        logging.error(f"Veritabanı dosyası gizlenemedi: {db_path}")
except Exception as e:
    logging.error(f"Veritabanı başlatma hatası: {e}")
    raise

# =============================
# Röle bağlantısı (opsiyonel)
# =============================
try:
    rolu = serial.Serial("COM3", 9600)
    logging.info("Röle bağlantısı başarılı")
except Exception as e:
    logging.warning(f"Röle bağlantısı başarısız: {e}. Röle devre dışı.")
    rolu = None


def kapiyi_ac():
    """Röleyi kısa süre tetikler (A/a)."""
    if rolu:
        try:
            rolu.write(b'A')  # Aç
            time.sleep(1)
            rolu.write(b'a')  # Kapat
            logging.info("Kapı açıldı")
        except Exception as e:
            logging.error(f"Röle işlemi hatası: {e}")
    else:
        logging.warning("Röle bağlı değil, kapı açılamadı")


# =============================
# Yardımcılar
# =============================
def hash_password(password):
    """Şifreyi SHA-256 ile hash'ler."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, hashed_password):
    """Girilen şifrenin hash'ini doğrular."""
    return hash_password(password) == hashed_password


def four_point_transform(image, pts):
    try:
        pts = pts.reshape(4, 2)
        rect = np.zeros((4, 2), dtype="float32")
        s = pts.sum(axis=1)
        rect[0] = pts[np.argmin(s)]
        rect[2] = pts[np.argmax(s)]
        diff = np.diff(pts, axis=1)
        rect[1] = pts[np.argmin(diff)]
        rect[3] = pts[np.argmax(diff)]
        (tl, tr, br, bl) = rect
        widthA = np.linalg.norm(br - bl)
        widthB = np.linalg.norm(tr - tl)
        maxWidth = max(int(widthA), int(widthB))
        heightA = np.linalg.norm(tr - br)
        heightB = np.linalg.norm(tl - bl)
        maxHeight = max(int(heightA), int(heightB))
        dst = np.array([[0, 0], [maxWidth - 1, 0], [maxWidth - 1, maxHeight - 1], [0, maxHeight - 1]], dtype="float32")
        M = cv2.getPerspectiveTransform(rect, dst)
        warped = cv2.warpPerspective(image, M, (maxWidth, maxHeight))
        return warped
    except Exception as e:
        logging.error(f"Perspektif dönüşüm hatası: {e}")
        return None


def detect_plate(frame):
    try:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        blur = cv2.bilateralFilter(gray, 11, 17, 17)
        edged = cv2.Canny(blur, 30, 200)
        contours, _ = cv2.findContours(edged.copy(), cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        contours = sorted(contours, key=cv2.contourArea, reverse=True)[:10]
        for c in contours:
            peri = cv2.arcLength(c, True)
            approx = cv2.approxPolyDP(c, 0.018 * peri, True)
            if len(approx) == 4:
                warped = four_point_transform(gray, approx)
                if warped is not None:
                    text = pytesseract.image_to_string(warped, config='--psm 8')
                    match = re.findall(r'\b\d{2}\s?[A-Z]{1,3}\s?\d{1,4}\b', text.upper())
                    if match:
                        return match[0].replace(" ", "").strip()
        return None
    except Exception as e:
        logging.error(f"Plaka tespit hatası: {e}")
        return None


# Zaman bazlı tekrar okuma engelleme
son_okunanlar = {}
bekleme_suresi = 10


def islem_yapilabilir(plaka):
    simdi = time.time()
    if plaka in son_okunanlar:
        if simdi - son_okunanlar[plaka] < bekleme_suresi:
            return False
    son_okunanlar[plaka] = simdi
    return True


# Veritabanı işlemleri
def is_plate_registered(plate):
    try:
        cursor.execute("SELECT 1 FROM plates WHERE plate=?", (plate.upper(),))
        return cursor.fetchone() is not None
    except Exception as e:
        logging.error(f"Plaka kontrol hatası: {e}")
        return False


def add_plate_to_db(plate):
    try:
        cursor.execute("INSERT OR IGNORE INTO plates(plate) VALUES (?)", (plate.upper(),))
        conn.commit()
    except sqlite3.IntegrityError as e:
        logging.warning(f"Plaka ekleme hatası: {e}")
        pass


def remove_plate_from_db(plate):
    try:
        cursor.execute("DELETE FROM plates WHERE plate=?", (plate.upper(),))
        conn.commit()
    except Exception as e:
        logging.error(f"Plaka silme hatası: {e}")


def get_all_plates():
    try:
        cursor.execute("SELECT plate FROM plates ORDER BY plate")
        return [row[0] for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Plaka listesi alma hatası: {e}")
        return []


def is_user_registered(username):
    try:
        cursor.execute("SELECT 1 FROM users WHERE username=?", (username,))
        return cursor.fetchone() is not None
    except Exception as e:
        logging.error(f"Kullanıcı kontrol hatası: {e}")
        return False


def register_user(username, password):
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hash_password(password)))
        conn.commit()
        logging.info(f"Kullanıcı kaydedildi: {username}")
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"Kullanıcı adı zaten mevcut: {username}")
        return False


def verify_user(username, password):
    try:
        cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        if result:
            return verify_password(password, result[0])
        return False
    except Exception as e:
        logging.error(f"Kullanıcı doğrulama hatası: {e}")
        return False


def is_first_user():
    try:
        cursor.execute("SELECT COUNT(*) FROM users")
        return cursor.fetchone()[0] == 0
    except Exception as e:
        logging.error(f"Kullanıcı sayısı kontrol hatası: {e}")
        return True


# =============================
# Log Kayıt İşlemleri
# =============================
def create_log_table(date_str):
    """Belirtilen tarih için log tablosu oluşturur."""
    table_name = f"logs_{date_str.replace('-', '_')}"
    try:
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                timestamp TEXT,
                message TEXT
            )
            """
        )
        cursor.execute("INSERT OR IGNORE INTO log_dates (date) VALUES (?)", (date_str,))
        conn.commit()
    except Exception as e:
        logging.error(f"Log tablosu oluşturma hatası ({table_name}): {e}")


def save_log_to_db(timestamp, message):
    """Logu veritabanına kaydeder."""
    date_str = timestamp.split()[0]  # YYYY-MM-DD
    table_name = f"logs_{date_str.replace('-', '_')}"
    create_log_table(date_str)
    try:
        cursor.execute(f"INSERT INTO {table_name} (timestamp, message) VALUES (?, ?)", (timestamp, message))
        conn.commit()
    except Exception as e:
        logging.error(f"Log kaydetme hatası ({table_name}): {e}")


def cleanup_old_logs():
    """10 günden eski logları siler."""
    try:
        cursor.execute("SELECT date FROM log_dates ORDER BY date")
        dates = [row[0] for row in cursor.fetchall()]
        if len(dates) > 10:
            for old_date in dates[:-10]:
                table_name = f"logs_{old_date.replace('-', '_')}"
                cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
                cursor.execute("DELETE FROM log_dates WHERE date = ?", (old_date,))
                conn.commit()
                logging.info(f"Eski log tablosu silindi: {table_name}")
    except Exception as e:
        logging.error(f"Eski logları temizleme hatası: {e}")


def get_log_dates():
    """Mevcut log tarihlerini döndürür."""
    try:
        cursor.execute("SELECT date FROM log_dates ORDER BY date DESC")
        return [row[0] for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Log tarihlerini alma hatası: {e}")
        return []


def get_logs_for_date(date_str):
    """Belirtilen tarihe ait logları döndürür."""
    table_name = f"logs_{date_str.replace('-', '_')}"
    try:
        cursor.execute(f"SELECT timestamp, message FROM {table_name} ORDER BY timestamp")
        return [f"[{row[0]}] {row[1]}" for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Logları alma hatası ({table_name}): {e}")
        return []


# =============================
# Kamera yardımcıları
# =============================
def parse_camera_source(value: str):
    """Kullanıcı girişini kamera kaynağına çevirir: '0'/'1' -> int, URL -> string."""
    v = value.strip()
    if v.isdigit():
        return int(v)
    return v


def open_camera(source):
    try:
        cap = cv2.VideoCapture(source)
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        if not cap.isOpened():
            logging.error(f"Kamera açılamadı: {source}")
            return None
        return cap
    except Exception as e:
        logging.error(f"Kamera başlatma hatası: {source}, {e}")
        return None


# =============================
# Login GUI
# =============================
class LoginGUI:
    def __init__(self, root, on_success):
        self.root = root
        self.root.title("🔐 Giriş")
        self.style = ttk.Style("darkly")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        self.on_success = on_success

        self.is_register_mode = is_first_user()

        # Ana frame
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(fill=BOTH, expand=True)

        # Başlık
        ttk.Label(self.main_frame,
                  text="Kayıt" if self.is_register_mode else "Giriş",
                  font=("Segoe UI", 16, "bold")).pack(pady=10)

        # Kullanıcı adı
        ttk.Label(self.main_frame, text="Kullanıcı Adı:").pack(anchor=W)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(self.main_frame, textvariable=self.username_var)
        self.username_entry.pack(fill=X, pady=5)
        self.username_entry.focus()

        # Şifre
        ttk.Label(self.main_frame, text="Şifre:").pack(anchor=W)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.main_frame, textvariable=self.password_var, show="*")
        self.password_entry.pack(fill=X, pady=5)

        # Hata mesajı
        self.error_label = ttk.Label(self.main_frame, text="", bootstyle="danger")
        self.error_label.pack(pady=5)

        # Buton
        self.submit_button = ttk.Button(self.main_frame,
                                        text="Kayıt Ol" if self.is_register_mode else "Giriş Yap",
                                        bootstyle="success",
                                        command=self.submit)
        self.submit_button.pack(fill=X, pady=10)

        # Enter tuşu bağlama
        self.root.bind('<Return>', lambda event: self.submit())

    def submit(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not username or not password:
            self.error_label.config(text="Kullanıcı adı ve şifre gerekli!")
            return

        if self.is_register_mode:
            if register_user(username, password):
                self.error_label.config(text="Kayıt başarılı! Giriş yapılıyor...", bootstyle="success")
                self.root.after(1000, self.proceed)
            else:
                self.error_label.config(text="Bu kullanıcı adı zaten alınmış!")
        else:
            if verify_user(username, password):
                self.error_label.config(text="Giriş başarılı!", bootstyle="success")
                self.root.after(1000, self.proceed)
            else:
                self.error_label.config(text="Kullanıcı adı veya şifre yanlış!")

    def proceed(self):
        # Login frame'i temizle
        for widget in self.root.winfo_children():
            widget.destroy()
        self.on_success(self.root)


# =============================
# Plaka Yönetimi Penceresi
# =============================
class PlatesWindow:
    def __init__(self, parent, app):
        self.app = app  # LicensePlateGUI referansı
        self.root = tk.Toplevel(parent)
        self.root.title("🚙 Kayıtlı Plakalar")
        self.root.geometry("400x500")
        self.root.transient(parent)
        self.root.grab_set()

        # Plaka listesi
        self.plate_frame = ttk.LabelFrame(self.root, text="Kayıtlı Plakalar", padding=10)
        self.plate_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.plate_listbox = tk.Listbox(
            self.plate_frame,
            bg="#1e1e1e",
            fg="white",
            font=("Consolas", 12),
            selectbackground="#00bc8c",
            activestyle='none'
        )
        self.plate_listbox.pack(side=LEFT, fill=BOTH, expand=True)
        self.plate_scrollbar = ttk.Scrollbar(self.plate_frame, orient=VERTICAL, command=self.plate_listbox.yview)
        self.plate_scrollbar.pack(side=RIGHT, fill=Y)
        self.plate_listbox.config(yscrollcommand=self.plate_scrollbar.set)

        # Plaka girişi ve butonlar
        self.plate_entry = ttk.Entry(self.root)
        self.plate_entry.pack(fill=X, padx=10, pady=(5, 5))
        self.add_button = ttk.Button(self.root, text="➕ Plaka Ekle", bootstyle="success", command=self.add_plate)
        self.add_button.pack(fill=X, padx=10, pady=2)
        self.remove_button = ttk.Button(self.root, text="🗑️ Seçili Plakayı Sil", bootstyle="danger",
                                        command=self.remove_plate)
        self.remove_button.pack(fill=X, padx=10, pady=2)

        # Plaka listesini doldur
        self.update_plate_list()

        # Kapatma olayı
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def update_plate_list(self):
        self.plate_listbox.delete(0, tk.END)
        for plate in get_all_plates():
            self.plate_listbox.insert(tk.END, plate)

    def add_plate(self):
        plate = self.plate_entry.get().strip().upper()
        if plate:
            add_plate_to_db(plate)
            self.update_plate_list()
            self.app.log(f"Plaka eklendi: {plate}")
            logging.info(f"Plaka eklendi: {plate}")
            self.plate_entry.delete(0, tk.END)

    def remove_plate(self):
        selection = self.plate_listbox.curselection()
        if selection:
            plate = self.plate_listbox.get(selection[0])
            remove_plate_from_db(plate)
            self.update_plate_list()
            self.app.log(f"Plaka silindi: {plate}")
            logging.info(f"Plaka silindi: {plate}")

    def on_closing(self):
        self.root.destroy()


# =============================
# Ana GUI
# =============================
class LicensePlateGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🚦 Plaka Tanıma ve Kapı Kontrol Sistemi")
        self.style = ttk.Style("darkly")

        # Tam ekran yap
        self.root.attributes('-fullscreen', True)
        # Ekran çözünürlüğünü al
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        self.root.geometry(f"{screen_width}x{screen_height}+0+0")

        # Esc tuşu ile tam ekrandan çık
        self.root.bind('<Escape>', self.toggle_fullscreen)

        self.start_time = datetime.now()
        self.running = True
        self.paused = False
        self.is_fullscreen = True
        self.last_log_time = {}  # Tekrarlanan logları önlemek için

        # ---------- HEADER ----------
        self.header = ttk.Frame(root, padding=15)
        self.header.pack(fill=X)
        self.title_label = ttk.Label(
            self.header,
            text="Plaka Tanıma Sistemi",
            font=("Segoe UI", 18, "bold")
        )
        self.title_label.pack(side=LEFT)
        self.uptime_label = ttk.Label(self.header, text="Çalışma Süresi: 00:00:00", font=("Segoe UI", 12))
        self.uptime_label.pack(side=RIGHT)

        # ---------- BODY CONTAINER ----------
        self.body = ttk.Frame(root, padding=10)
        self.body.pack(fill=BOTH, expand=True)

        # Sol: Kamera alanı (iki kart)
        self.camera_frame = ttk.Frame(self.body)
        self.camera_frame.pack(side=LEFT, fill=BOTH, expand=True)

        # Kameraların eşit boyutlarda olması için bir grid kullan
        self.camera_frame.grid_rowconfigure(0, weight=1)
        self.camera_frame.grid_rowconfigure(1, weight=1)
        self.camera_frame.grid_columnconfigure(0, weight=1)

        self.entry_frame = ttk.LabelFrame(self.camera_frame, text="📷 Giriş Kamerası", padding=10, bootstyle="info")
        self.entry_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.entry_canvas = ttk.Label(self.entry_frame)
        self.entry_canvas.pack(fill=BOTH, expand=True)
        self.entry_status = ttk.Label(self.entry_frame, text="Bağlı Değil", bootstyle="danger")
        self.entry_status.pack(pady=6)

        self.exit_frame = ttk.LabelFrame(self.camera_frame, text="📷 Çıkış Kamerası", padding=10, bootstyle="info")
        self.exit_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.exit_canvas = ttk.Label(self.exit_frame)
        self.exit_canvas.pack(fill=BOTH, expand=True)
        self.exit_status = ttk.Label(self.exit_frame, text="Bağlı Değil", bootstyle="danger")
        self.exit_status.pack(pady=6)

        # Sağ: Sidebar
        self.sidebar = ttk.Frame(self.body, padding=8)
        self.sidebar.pack(side=RIGHT, fill=Y)

        # Kontroller
        self.control_frame = ttk.LabelFrame(self.sidebar, text="⚙️ Kontroller", padding=10)
        self.control_frame.pack(fill=X, pady=6)
        self.pause_button = ttk.Button(self.control_frame, text="⏸ Duraklat", bootstyle="warning",
                                       command=self.toggle_pause)
        self.pause_button.pack(fill=X, pady=4)
        self.gate_button = ttk.Button(self.control_frame, text="🔓 Kapıyı Aç", bootstyle="success", command=kapiyi_ac)
        self.gate_button.pack(fill=X, pady=4)
        self.fullscreen_button = ttk.Button(self.control_frame, text="🖥️ Tam Ekrandan Çık", bootstyle="info",
                                            command=self.toggle_fullscreen)
        self.fullscreen_button.pack(fill=X, pady=4)

        # Kamera ayarları
        self.camera_ip_frame = ttk.LabelFrame(self.sidebar, text="📡 Kamera Kaynakları", padding=10)
        self.camera_ip_frame.pack(fill=X, pady=6)
        ttk.Label(self.camera_ip_frame, text="Giriş Kamera (0/URL):").pack(anchor=W)
        self.entry_ip_var = tk.StringVar(value="0")
        self.entry_ip_entry = ttk.Entry(self.camera_ip_frame, textvariable=self.entry_ip_var)
        self.entry_ip_entry.pack(fill=X, pady=2)
        ttk.Label(self.camera_ip_frame, text="Çıkış Kamera (1/URL):").pack(anchor=W)
        self.exit_ip_var = tk.StringVar(value="1")
        self.exit_ip_entry = ttk.Entry(self.camera_ip_frame, textvariable=self.exit_ip_var)
        self.exit_ip_entry.pack(fill=X, pady=2)
        self.update_ip_button = ttk.Button(self.camera_ip_frame, text="🔄 Uygula", bootstyle="info",
                                           command=self.update_camera_ips)
        self.update_ip_button.pack(fill=X, pady=6)

        # Plaka yönetimi butonu
        self.plate_button = ttk.Button(self.sidebar, text="🚙 Kayıtlı Plakalar", bootstyle="info",
                                       command=self.open_plates_window)
        self.plate_button.pack(fill=X, pady=6)

        # Geçmiş Loglar
        self.log_history_frame = ttk.LabelFrame(self.sidebar, text="📜 Geçmiş Loglar", padding=10)
        self.log_history_frame.pack(fill=BOTH, expand=True, pady=6)
        self.log_date_var = tk.StringVar()
        self.log_date_combo = ttk.Combobox(self.log_history_frame, textvariable=self.log_date_var, state="readonly")
        self.log_date_combo.pack(fill=X, pady=2)
        self.log_date_combo.bind("<<ComboboxSelected>>", self.display_selected_log)
        self.log_history_text = tk.Text(
            self.log_history_frame,
            height=15,
            bg="#1e1e1e",
            fg="white",
            font=("Consolas", 11),
            state="disabled"
        )
        self.log_history_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.log_history_scrollbar = ttk.Scrollbar(self.log_history_frame, orient=VERTICAL,
                                                   command=self.log_history_text.yview)
        self.log_history_scrollbar.pack(side=RIGHT, fill=Y)
        self.log_history_text['yscrollcommand'] = self.log_history_scrollbar.set

        # Röle durumu
        self.relay_status = ttk.Label(root, text="Röle: " + ("Bağlı" if rolu else "Bağlı Değil"),
                                      bootstyle=("success" if rolu else "danger"))
        self.relay_status.pack(side=BOTTOM, pady=(0, 10))

        # Kameraları başlat
        self.giris_kamera = open_camera(parse_camera_source(self.entry_ip_var.get()))
        self.cikis_kamera = open_camera(parse_camera_source(self.exit_ip_var.get()))

        # Log tarihlerini doldur
        self.update_log_dates()

        # Kamera işleme threadi
        self.thread = threading.Thread(target=self.process_cameras, daemon=True)
        self.thread.start()

        # Uptime başlat
        self.update_uptime()

        # Kapatma olayı
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def open_plates_window(self):
        """Kayıtlı plakalar penceresini açar."""
        self.plates_window = PlatesWindow(self.root, self)

    def toggle_fullscreen(self, event=None):
        """Tam ekran modunu açar/kapatır."""
        self.is_fullscreen = not self.is_fullscreen
        self.root.attributes('-fullscreen', self.is_fullscreen)
        if self.is_fullscreen:
            self.fullscreen_button.config(text="🖥️ Tam Ekrandan Çık", bootstyle="info")
            self.root.geometry(f"{self.root.winfo_screenwidth()}x{self.root.winfo_screenheight()}+0+0")
        else:
            self.fullscreen_button.config(text="🖥️ Tam Ekran Yap", bootstyle="info")
            self.root.geometry("1600x900+0+0")
            self.root.minsize(1200, 720)

    def log(self, message):
        """Tekrarlanan logları önlemek için zaman kontrolü eklenmiş loglama."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_key = f"{timestamp}:{message}"
        if log_key not in self.last_log_time or (time.time() - self.last_log_time[log_key]) > 1:
            # Arayüzde anında güncelle
            self.log_history_text.config(state="normal")
            self.log_history_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_history_text.see(tk.END)
            self.log_history_text.config(state="disabled")

            # Veritabanına kaydet
            save_log_to_db(timestamp, message)
            logging.info(f"Log kaydedildi (Terminal): {message}")

            self.last_log_time[log_key] = time.time()

            # Log tarihlerini ve içeriğini güncelle
            self.update_log_dates()
            current_date = datetime.now().strftime("%Y-%m-%d")
            if self.log_date_var.get() == current_date:
                self.root.after(100, self.display_selected_log, None)  # 100ms gecikme ile güncelle

    def update_live_logs(self, timestamp, message):
        """Seçilen tarihe anlık log ekler."""
        self.log_history_text.config(state="normal")
        self.log_history_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_history_text.see(tk.END)
        self.log_history_text.config(state="disabled")

    def update_log_dates(self):
        """Log tarihlerini günceller ve combobox'ı doldurur."""
        dates = get_log_dates()
        current_date = datetime.now().strftime("%Y-%m-%d")
        if current_date not in dates:
            dates.insert(0, current_date)  # Güncel tarihi ekle
        self.log_date_var.set("")
        self.log_date_combo['values'] = dates
        if dates:
            self.log_date_var.set(dates[0])  # En son tarihi seç
            self.display_selected_log(None)
        logging.debug(f"Log tarihleri güncellendi: {dates}")

    def display_selected_log(self, event):
        """Seçilen tarihe ait logları gösterir."""
        date_str = self.log_date_var.get()
        if not date_str:
            return
        self.log_history_text.config(state="normal")
        self.log_history_text.delete(1.0, tk.END)
        logs = get_logs_for_date(date_str)
        logging.debug(f"Loglar çekildi için {date_str}: {logs}")
        for log in logs:
            self.log_history_text.insert(tk.END, f"{log}\n")
        self.log_history_text.config(state="disabled")
        self.log_history_text.see(tk.END)

    def update_uptime(self):
        if self.running:
            uptime = datetime.now() - self.start_time
            self.uptime_label.config(text=f"Çalışma Süresi: {str(uptime).split('.')[0]}")
            self.root.after(1000, self.update_uptime)

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_button.config(
            text=("▶️ Devam Et" if self.paused else "⏸ Duraklat"),
            bootstyle=("success" if self.paused else "warning")
        )
        self.log("Sistem " + ("duraklatıldı" if self.paused else "devam ediyor"))

    def update_camera_ips(self):
        try:
            if self.giris_kamera and self.giris_kamera.isOpened():
                self.giris_kamera.release()
            if self.cikis_kamera and self.cikis_kamera.isOpened():
                self.cikis_kamera.release()
        except Exception as e:
            logging.error(f"Kamera kapatma hatası: {e}")

        entry_src = parse_camera_source(self.entry_ip_var.get())
        exit_src = parse_camera_source(self.exit_ip_var.get())
        self.giris_kamera = open_camera(entry_src)
        self.cikis_kamera = open_camera(exit_src)
        self.log(f"Kamera kaynakları güncellendi: Giriş({self.entry_ip_var.get()}) / Çıkış({self.exit_ip_var.get()})")

    def process_cameras(self):
        while self.running:
            if self.paused:
                time.sleep(0.1)
                continue

            # Giriş kamerası
            if self.giris_kamera:
                ret1, frame1 = self.giris_kamera.read()
                if ret1 and frame1 is not None:
                    self.entry_status.config(text="Bağlı", bootstyle="success")
                    plaka1 = detect_plate(frame1)
                    frame1_small = cv2.resize(frame1, (640, 360))
                    frame1_rgb = cv2.cvtColor(frame1_small, cv2.COLOR_BGR2RGB)
                    img1 = Image.fromarray(frame1_rgb)
                    imgtk1 = ImageTk.PhotoImage(image=img1)
                    self.entry_canvas.imgtk = imgtk1
                    self.entry_canvas.configure(image=imgtk1)

                    if plaka1 and islem_yapilabilir(plaka1):
                        self.log(f"Giriş Kamerası > Plaka: {plaka1}")
                        if is_plate_registered(plaka1):
                            self.log("Kayıtlı plaka - Giriş izni verildi")
                            kapiyi_ac()
                        else:
                            self.log("Kayıtlı değil - Giriş reddedildi")
                else:
                    self.entry_status.config(text="Bağlı Değil", bootstyle="danger")

            # Çıkış kamerası
            if self.cikis_kamera:
                ret2, frame2 = self.cikis_kamera.read()
                if ret2 and frame2 is not None:
                    self.exit_status.config(text="Bağlı", bootstyle="success")
                    plaka2 = detect_plate(frame2)
                    frame2_small = cv2.resize(frame2, (640, 360))
                    frame2_rgb = cv2.cvtColor(frame2_small, cv2.COLOR_BGR2RGB)
                    img2 = Image.fromarray(frame2_rgb)
                    imgtk2 = ImageTk.PhotoImage(image=img2)
                    self.exit_canvas.imgtk = imgtk2
                    self.exit_canvas.configure(image=imgtk2)

                    if plaka2 and islem_yapilabilir(plaka2):
                        self.log(f"Çıkış Kamerası > Plaka: {plaka2}")
                        if is_plate_registered(plaka2):
                            self.log("Kayıtlı plaka - Çıkış izni verildi")
                            kapiyi_ac()
                        else:
                            self.log("Kayıtlı değil - Çıkış reddedildi")
                else:
                    self.exit_status.config(text="Bağlı Değil", bootstyle="danger")

            time.sleep(0.05)

    def on_closing(self):
        self.running = False
        try:
            if self.giris_kamera and self.giris_kamera.isOpened():
                self.giris_kamera.release()
            if self.cikis_kamera and self.cikis_kamera.isOpened():
                self.cikis_kamera.release()
        except Exception as e:
            logging.error(f"Kamera kapatma hatası: {e}")
        try:
            if rolu:
                rolu.close()
        except Exception as e:
            logging.error(f"Röle kapatma hatası: {e}")
        try:
            conn.close()
        except Exception as e:
            logging.error(f"Veritabanı kapatma hatası: {e}")
        self.root.destroy()


# =============================
# Ana program
# =============================
def start_main_gui(root):
    app = LicensePlateGUI(root)
    app.log("Sistem başlatıldı")


if __name__ == "__main__":
    root = ttk.Window()
    login_app = LoginGUI(root, start_main_gui)
    root.mainloop()
