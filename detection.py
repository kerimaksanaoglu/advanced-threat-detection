import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import tkinter as tk
from tkinter import filedialog
import threading
import pystray
from PIL import Image
import time
import random
import datetime
import os
import requests
import customtkinter as ctk


class AIThreatDetectionSystem:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.features = ['ip_reputation', 'traffic_volume', 'unusual_port_access', 'encryption_level', 'payload_size']
        self.is_running = False
        self.model_file = "threat_model.joblib"
        self.load_or_train_model()

    def preprocess_data(self, raw_data):
        return np.array(raw_data)

    def train_model_with_data(self, X, y, n_estimators=100, max_depth=None, min_samples_split=2):
        self.model = RandomForestClassifier(n_estimators=n_estimators,
                                            max_depth=max_depth,
                                            min_samples_split=min_samples_split,
                                            random_state=42)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        self.save_model()
        return accuracy, classification_report(y_test, y_pred)

    def load_or_train_model(self):
        if os.path.exists(self.model_file):
            self.load_model()
        else:
            print("Eğitilmiş model bulunamadı. Yeni model eğitiliyor...")
            X = np.random.rand(1000, 5)
            y = np.random.randint(2, size=1000)
            self.train_model_with_data(X, y)

    def check_ip_reputation(self, ip_address):
        api_key = "your_abuseipdb_api_key"  # AbuseIPDB API anahtarınızı buraya ekleyin
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data['data']['abuseConfidenceScore']
        except:
            pass
        return 0

    def detect_threat(self, input_data):
        processed_data = self.preprocess_data(input_data)
        prediction = self.model.predict(processed_data.reshape(1, -1))
        threat_probability = self.model.predict_proba(processed_data.reshape(1, -1))[0][1]

        result = "Tehdit Algılandı" if prediction[0] == 1 else "Tehdit Algılanmadı"

        ip_reputation_score = self.check_ip_reputation(str(input_data[0]))

        file_info = self.get_random_file_info()
        service_info = self.get_random_service_info()

        details = {
            "zaman": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sonuç": result,
            "tehdit_olasılığı": f"{threat_probability:.2%}",
            "ip_itibarı": f"{ip_reputation_score}%",
            "trafik_hacmi": f"{input_data[1]:.2f}",
            "olağandışı_port_erişimi": f"{input_data[2]:.2f}",
            "şifreleme_seviyesi": f"{input_data[3]:.2f}",
            "payload_boyutu": f"{input_data[4]:.2f}",
            "ilgili_dosya": file_info,
            "ilgili_hizmet": service_info
        }

        return result, details

    def get_random_file_info(self):
        files = [
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Program Files\\SuspiciousApp\\malware.exe",
            "C:\\Users\\Admin\\Downloads\\unknown_file.dll",
            "C:\\Windows\\explorer.exe",
            "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
        ]
        return random.choice(files)

    def get_random_service_info(self):
        services = [
            "Windows Update",
            "Remote Desktop Services",
            "DNS Client",
            "Windows Defender Antivirus Service",
            "Suspicious Background Service"
        ]
        return random.choice(services)

    def save_model(self):
        joblib.dump(self.model, self.model_file)

    def load_model(self):
        self.model = joblib.load(self.model_file)

    def start_monitoring(self, callback):
        self.is_running = True
        while self.is_running:
            sample_data = [random.random() for _ in range(5)]
            result, details = self.detect_threat(sample_data)
            callback(result, details)
            time.sleep(5)

    def stop_monitoring(self):
        self.is_running = False


class ThreatDetectionGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Gelişmiş Tehdit Algılama Sistemi")
        self.master.geometry("800x600")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.system = AIThreatDetectionSystem()

        self.create_widgets()
        self.create_tray_icon()

    def create_widgets(self):
        self.sidebar = ctk.CTkFrame(self.master, width=200, corner_radius=0)
        self.sidebar.pack(side="left", fill="y", padx=20, pady=20)

        self.logo = ctk.CTkLabel(self.sidebar, text="Tehdit Algılama", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo.pack(padx=20, pady=20)

        self.train_button = ctk.CTkButton(self.sidebar, text="Model Eğitim Ayarları", command=self.open_train_dialog)
        self.train_button.pack(padx=20, pady=10)

        self.start_button = ctk.CTkButton(self.sidebar, text="İzlemeyi Başlat", command=self.start_monitoring)
        self.start_button.pack(padx=20, pady=10)

        self.stop_button = ctk.CTkButton(self.sidebar, text="İzlemeyi Durdur", command=self.stop_monitoring)
        self.stop_button.pack(padx=20, pady=10)

        self.status_label = ctk.CTkLabel(self.sidebar, text="Durum: Bekleniyor")
        self.status_label.pack(padx=20, pady=20)

        self.main_frame = ctk.CTkFrame(self.master)
        self.main_frame.pack(side="right", fill="both", expand=True, padx=20, pady=20)

        self.log_area = ctk.CTkTextbox(self.main_frame, width=500, height=400)
        self.log_area.pack(padx=20, pady=20, fill="both", expand=True)

        self.progress_bar = ctk.CTkProgressBar(self.main_frame, orientation="horizontal")
        self.progress_bar.pack(padx=20, pady=10, fill="x")
        self.progress_bar.set(0)

    def create_tray_icon(self):
        image = Image.new('RGB', (64, 64), color=(0, 255, 0))
        menu = pystray.Menu(pystray.MenuItem('Çıkış', self.quit_window))
        self.icon = pystray.Icon("name", image, "Tehdit Algılama Sistemi", menu)
        threading.Thread(target=self.icon.run, daemon=True).start()

    def open_train_dialog(self):
        dialog = ctk.CTkToplevel(self.master)
        dialog.title("Model Eğitim Ayarları")
        dialog.geometry("400x300")

        ctk.CTkLabel(dialog, text="Veri Seti:").pack(pady=5)
        self.data_path = ctk.StringVar()
        ctk.CTkEntry(dialog, textvariable=self.data_path).pack(pady=5)
        ctk.CTkButton(dialog, text="Veri Seti Seç", command=self.select_data).pack(pady=5)

        ctk.CTkLabel(dialog, text="Ağaç Sayısı:").pack(pady=5)
        self.n_estimators = ctk.IntVar(value=100)
        ctk.CTkEntry(dialog, textvariable=self.n_estimators).pack(pady=5)

        ctk.CTkLabel(dialog, text="Maksimum Derinlik:").pack(pady=5)
        self.max_depth = ctk.IntVar(value=0)
        ctk.CTkEntry(dialog, textvariable=self.max_depth).pack(pady=5)

        ctk.CTkLabel(dialog, text="Minimum Örnek Bölme:").pack(pady=5)
        self.min_samples_split = ctk.IntVar(value=2)
        ctk.CTkEntry(dialog, textvariable=self.min_samples_split).pack(pady=5)

        ctk.CTkButton(dialog, text="Modeli Eğit", command=self.train_model_with_params).pack(pady=20)

    def select_data(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file_path:
            self.data_path.set(file_path)

    def train_model_with_params(self):
        try:
            data = pd.read_csv(self.data_path.get())
            X = data[self.system.features].values
            y = data['target'].values  # 'target' sütununun veri setinizde olduğunu varsayıyoruz

            max_depth = None if self.max_depth.get() == 0 else self.max_depth.get()

            accuracy, report = self.system.train_model_with_data(
                X, y,
                n_estimators=self.n_estimators.get(),
                max_depth=max_depth,
                min_samples_split=self.min_samples_split.get()
            )

            self.log_area.insert("end",
                                 f"Model Eğitim Sonuçları:\nDoğruluk: {accuracy}\n\nSınıflandırma Raporu:\n{report}\n\n")
            self.log_area.see("end")
        except Exception as e:
            self.log_area.insert("end", f"Eğitim sırasında hata oluştu: {str(e)}\n\n")
            self.log_area.see("end")

    def start_monitoring(self):
        self.status_label.configure(text="Durum: Çalışıyor")
        self.icon.icon = Image.new('RGB', (64, 64), color=(0, 255, 0))
        threading.Thread(target=self.system.start_monitoring, args=(self.update_log,), daemon=True).start()

    def stop_monitoring(self):
        self.system.stop_monitoring()
        self.status_label.configure(text="Durum: Durduruldu")
        self.icon.icon = Image.new('RGB', (64, 64), color=(255, 0, 0))

    def update_log(self, result, details):
        log_entry = f"Zaman: {details['zaman']}\n"
        log_entry += f"Sonuç: {result}\n"
        log_entry += f"Tehdit Olasılığı: {details['tehdit_olasılığı']}\n"
        log_entry += f"IP İtibarı: {details['ip_itibarı']}\n"
        log_entry += f"Trafik Hacmi: {details['trafik_hacmi']}\n"
        log_entry += f"Olağandışı Port Erişimi: {details['olağandışı_port_erişimi']}\n"
        log_entry += f"Şifreleme Seviyesi: {details['şifreleme_seviyesi']}\n"
        log_entry += f"Payload Boyutu: {details['payload_boyutu']}\n"
        log_entry += f"İlgili Dosya: {details['ilgili_dosya']}\n"
        log_entry += f"İlgili Hizmet: {details['ilgili_hizmet']}\n"
        log_entry += "-" * 50 + "\n"

        self.log_area.insert("end", log_entry)
        self.log_area.see("end")

        threat_probability = float(details['tehdit_olasılığı'].strip('%')) / 100
        self.progress_bar.set(threat_probability)

    def quit_window(self):
        self.system.stop_monitoring()
        self.master.quit()
        self.icon.stop()


if __name__ == "__main__":
    root = ctk.CTk()
    app = ThreatDetectionGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.quit_window)
    root.mainloop()
