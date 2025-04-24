import sys, requests, json, cv2, time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QFileDialog,
    QVBoxLayout, QHBoxLayout, QWidget, QTextEdit, QProgressBar,
    QStackedWidget, QListWidget, QListWidgetItem, QComboBox
)
from PyQt6.QtGui import QPixmap, QPalette, QColor, QIcon
from PyQt6.QtCore import Qt

URLSCAN_API_KEY = "01960bce-fff1-74ba-9172-037bcf9b378d"
VT_API_KEY = "026d49d28a07876273802d0546083d7fa2e454e9fe9221a69a2a3f6302dc3def"

class QRGuard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QR Guard")
        self.setGeometry(200, 200, 900, 600)
        self.setWindowIcon(QIcon("logo.png"))
        self.init_ui()

    def init_ui(self):
        self.layout = QHBoxLayout()
        self.menu = QListWidget()
        self.menu.setMaximumWidth(200)
        self.menu.addItem("📂 Skanuj obraz")
        self.menu.addItem("📷 Kamera")
        self.menu.addItem("ℹ️ Informacje")
        self.menu.addItem("❌ Wyjdź")
        self.menu.currentRowChanged.connect(self.menu_clicked)

        self.image = QLabel("Tu pojawi się obraz QR")
        self.image.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.progress = QProgressBar()
        self.progress.setValue(0)

        self.theme = QComboBox()
        self.theme.addItems(["Ciemny", "Jasny"])
        self.theme.currentIndexChanged.connect(self.switch_theme)

        right = QVBoxLayout()
        right.addWidget(self.image)
        right.addWidget(self.output)
        right.addWidget(self.progress)
        right.addWidget(self.theme)

        self.layout.addWidget(self.menu)
        self.layout.addLayout(right)

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)
        self.set_dark()

    def switch_theme(self):
        if self.theme.currentText() == "Ciemny":
            self.set_dark()
        else:
            self.set_light()

    def set_dark(self):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.ColorRole.Base, QColor(45, 45, 45))
        palette.setColor(QPalette.ColorRole.Text, QColor(200, 200, 200))
        self.setPalette(palette)

    def set_light(self):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0))
        self.setPalette(palette)

    def menu_clicked(self, index):
        if index == 0:
            self.load_image()
        elif index == 1:
            self.scan_camera()
        elif index == 2:
            self.show_info()
        elif index == 3:
            sys.exit()

    def load_image(self):
        file, _ = QFileDialog.getOpenFileName(self, "Wybierz obraz QR", "", "Obrazy (*.png *.jpg *.jpeg)")
        if file:
            self.image.setPixmap(QPixmap(file).scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
            self.decode_and_analyze(file)

    def scan_camera(self):
        cap = cv2.VideoCapture(0)
        detector = cv2.QRCodeDetector()
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            data, bbox, _ = detector.detectAndDecode(frame)
            cv2.imshow("QR Guard – Kamera (naciśnij q)", frame)
            if data:
                cap.release()
                cv2.destroyAllWindows()
                self.image.setPixmap(QPixmap("logo.png").scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
                self.analyze(data)
                return
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        cap.release()
        cv2.destroyAllWindows()

    def decode_and_analyze(self, path):
        image = cv2.imread(path)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(image)
        if data:
            self.analyze(data)
        else:
            self.output.setText("❌ Nie udało się odczytać kodu QR.")

    def analyze(self, url):
        self.output.setText(f"🔎 Zawartość QR:\n{url}\n\n⏳ Trwa analiza...")
        score = 100

        # VirusTotal
        try:
            headers = {"x-apikey": VT_API_KEY}
            res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
            if res.status_code == 200:
                url_id = res.json()["data"]["id"]
                time.sleep(2)
                report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers)
                stats = report.json()["data"]["attributes"]["stats"]
                mal, sus, total = stats.get("malicious", 0), stats.get("suspicious", 0), sum(stats.values())
                ok = total - mal - sus
                score -= (mal + sus) * 10

                self.output.append(
                    f"🦠 VirusTotal – analiza {total} silników antywirusowych:\n"
                    f"✅ {ok} nie wykryło zagrożeń\n"
                    f"❌ {mal} wykryło zagrożenie\n"
                    f"⚠️ {sus} uznało stronę za podejrzaną"
                )

                if mal >= 3:
                    self.output.append("❌ Wysokie zagrożenie! Większość silników ostrzega.")
                elif mal >= 1:
                    self.output.append("⚠️ Co najmniej jeden silnik antywirusowy wykrył zagrożenie.")
                else:
                    self.output.append("✅ Brak zagrożeń według VirusTotal.")
        except Exception as e:
            self.output.append(f"❌ Błąd VirusTotal: {e}")

        # urlscan.io
        try:
            headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
            data = {"url": url, "visibility": "public"}
            scan = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)).json()
            uuid = scan.get("uuid")
            if not uuid:
                raise Exception("Brak UUID w odpowiedzi.")
            time.sleep(8)
            result = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/").json()
            page = result.get("page", {})

            ip = page.get("ip", "Brak")
            country = page.get("country", "Brak")
            org = page.get("asnname", "Brak")
            ssl = page.get("tlsValidDaysLeft", "Brak")
            ssl_int = int(ssl) if str(ssl).isdigit() else 0

            self.output.append(f"🌐 IP serwera: {ip}")
            self.output.append(f"🌍 Kraj: {country}")
            self.output.append(f"🏢 Organizacja (ASN): {org}")
            self.output.append(f"🔐 Certyfikat SSL ważny jeszcze: {ssl} dni")

            if ssl_int < 10:
                score -= 10
        except Exception as e:
            self.output.append(f"❌ Błąd urlscan.io: {e}")

        # Pasek poziomu bezpieczeństwa
        score = max(0, min(100, score))
        self.progress.setValue(score)
        if score >= 90:
            self.progress.setStyleSheet("QProgressBar::chunk { background-color: #4CAF50; }")
            self.output.append(f"🟢 Poziom bezpieczeństwa: {score}% – Bezpiecznie ✅")
        elif score >= 60:
            self.progress.setStyleSheet("QProgressBar::chunk { background-color: #FFC107; }")
            self.output.append(f"🟡 Poziom bezpieczeństwa: {score}% – Zachowaj ostrożność ⚠️")
        else:
            self.progress.setStyleSheet("QProgressBar::chunk { background-color: #F44336; }")
            self.output.append(f"🔴 Poziom bezpieczeństwa: {score}% – NIEBEZPIECZNE ❌")

    def show_info(self):
        self.output.setText(
            "ℹ️ Informacja prawna:\n\n"
            "QR Guard nie gwarantuje 100% bezpieczeństwa.\n"
            "Wchodzisz na stronę na własną odpowiedzialność.\n\n"
            "Podejrzenia zgłaszaj do CERT Polska lub organów ścigania.\n\n"
            "Podstawa prawna:\n"
            "– Art. 287 KK (oszustwa komputerowe)\n"
            "– Art. 286 KK (oszustwo)\n"
            "– RODO (UE 2016/679)"
        )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QRGuard()
    window.show()
    sys.exit(app.exec())
