import sys
import os
import time
import hashlib
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit, QTextEdit, QProgressBar
from PyQt5.QtCore import QThread, pyqtSignal
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

class Gold211Encoder:
    morse_code_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
        'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
        'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
        '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ' ': '/'
    }

    braille_dict = {
        'A': '100000', 'B': '101000', 'C': '110000', 'D': '110100', 'E': '100100', 'F': '111000',
        'G': '111100', 'H': '101100', 'I': '011000', 'J': '011100', 'K': '100010', 'L': '101010',
        'M': '110010', 'N': '110110', 'O': '100110', 'P': '111010', 'Q': '111110', 'R': '101110',
        'S': '011010', 'T': '011110', 'U': '100011', 'V': '101011', 'W': '011101', 'X': '110011',
        'Y': '110111', 'Z': '100111', ' ': '000000', '1': '100000', '2': '101000', '3': '110000',
        '4': '110100', '5': '100100', '6': '111000', '7': '111100', '8': '101100', '9': '011000',
        '0': '011100'
    }

    egyptian_dict = {
        'A': '𓄿', 'B': '𓃀', 'C': '𓍿', 'D': '𓂧', 'E': '𓇌', 'F': '𓆑', 'G': '𓎼', 'H': '𓎛',
        'I': '𓇋', 'J': '𓆥', 'K': '𓎡', 'L': '𓃭', 'M': '𓅓', 'N': '𓈖', 'O': '𓅱', 'P': '𓉺',
        'Q': '𓐍', 'R': '𓂋', 'S': '𓇋𓄿', 'T': '𓂧𓄿', 'U': '𓅱𓎼', 'V': '𓆑𓎛', 'W': '𓎡𓍿',
        'X': '𓂝𓇋', 'Y': '𓇋𓄿', 'Z': '𓎛𓋴', ' ': '⯇'
    }

    @staticmethod
    def to_morse(text):
        return ' '.join([Gold211Encoder.morse_code_dict.get(char.upper(), char) for char in text])

    @staticmethod
    def to_braille(text):
        return ' '.join([Gold211Encoder.braille_dict.get(char.upper(), char) for char in text])

    @staticmethod
    def to_egyptian(text):
        return ''.join([Gold211Encoder.egyptian_dict.get(char.upper(), char) for char in text])

class EncryptionThread(QThread):
    progress_signal = pyqtSignal(str)
    update_progress = pyqtSignal(int)

    def __init__(self, directory, password):
        super().__init__()
        self.directory = directory
        self.password = password

    def run(self):
        self.progress_signal.emit('Starting encryption...')
        time.sleep(1)

        key = self.derive_key(self.password)

        if os.path.exists(self.directory):
            total_files = sum([len(files) for _, _, files in os.walk(self.directory)])
            encrypted_files = 0

            for root, dirs, files in os.walk(self.directory):
                for file in files:
                    full_path = os.path.join(root, file)
                    self.encrypt_file(full_path, key)
                    encrypted_files += 1
                    progress = (encrypted_files / total_files) * 100
                    self.update_progress.emit(int(progress))
                    self.progress_signal.emit(f'Encrypted: {file}')

            self.progress_signal.emit('Encryption completed!')
        else:
            self.progress_signal.emit('Error: Directory not found.')

    def derive_key(self, password):
        salt = b'some_salt'
        return scrypt(password.encode('utf-8'), salt, dkLen=32, N=2**14, r=8, p=1)

    def encrypt_file(self, filepath, key):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)

            b64_data = base64.b64encode(ciphertext).decode('utf-8')

            morse = Gold211Encoder.to_morse(b64_data)
            braille = Gold211Encoder.to_braille(b64_data)
            egyptian = Gold211Encoder.to_egyptian(b64_data)

            result = f"---Morse Code---\n{morse}\n\n"
            result += f"---Braille---\n{braille}\n\n"
            result += f"---Egyptian Hieroglyphs---\n{egyptian}\n\n"
            result += f"---Base64---\n{b64_data}\n"

            with open(filepath + '.enc.multilingual', 'w', encoding='utf-8') as f:
                f.write(result)

            os.remove(filepath)
        except Exception as e:
            self.progress_signal.emit(f'Error encrypting {filepath}: {str(e)}')

class Gold211UI(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Gold-211 Multilingual Encryption')
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        self.status_label = QLabel('Status: Ready', self)
        layout.addWidget(self.status_label)

        self.directory_input = QLineEdit(self)
        self.directory_input.setPlaceholderText('Enter directory path to encrypt')
        layout.addWidget(self.directory_input)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('Enter password')
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.progress_bar = QProgressBar(self)
        layout.addWidget(self.progress_bar)

        self.output_text = QTextEdit(self)
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)

        self.encrypt_button = QPushButton('Start Encryption', self)
        self.encrypt_button.clicked.connect(self.start_encryption)
        layout.addWidget(self.encrypt_button)

        self.setLayout(layout)

    def start_encryption(self):
        directory = self.directory_input.text()
        password = self.password_input.text()

        self.thread = EncryptionThread(directory, password)
        self.thread.progress_signal.connect(self.show_message)
        self.thread.update_progress.connect(self.progress_bar.setValue)
        self.thread.start()

    def show_message(self, message):
        self.status_label.setText(f'Status: {message}')
        self.output_text.append(message)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Gold211UI()
    window.show()
    sys.exit(app.exec_())