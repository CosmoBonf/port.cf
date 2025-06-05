import os
import socket
import subprocess
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QTextEdit, QVBoxLayout
import psutil  # Para obter informações de IP e MAC

def check_for_updates():
    try:
        result = subprocess.run(['pacman', '-Qu'], capture_output=True, text=True)
        if result.stdout:
            return "O sistema possui pacotes desatualizados."
        else:
            return "O sistema está atualizado."
    except Exception as e:
        return f"Erro ao verificar atualizações: {e}"

def check_weak_passwords():
    weak_passwords = []
    with open('/etc/passwd', 'r') as f:
        for line in f.readlines():
            if ":x:" in line:
                user = line.split(':')[0]
                weak_passwords.append(user)
    return weak_passwords

def check_file_permissions():
    insecure_files = []
    for root, dirs, files in os.walk('/'):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                permissions = oct(os.stat(file_path).st_mode)[-3:]
                if permissions[0] == '7':
                    insecure_files.append(file_path)
            except Exception as e:
                print(f"Erro ao acessar {file_path}: {e}")
    return insecure_files

def get_users_with_full_access():
    full_access_users = []
    with open('/etc/passwd', 'r') as f:
        for line in f.readlines():
            user_info = line.split(':')
            user = user_info[0]
            uid = int(user_info[2])
            if uid == 0:  # UID 0 é o root
                full_access_users.append(user)
    return full_access_users

def get_open_ports():
    open_ports = []
    for port in range(1, 65535):  # Verifica todas as portas
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex(('127.0.0.1', port)) == 0:  # Testa a conexão
                open_ports.append(port)
    return open_ports

def get_network_info():
    ip_info = psutil.net_if_addrs()
    mac_info = psutil.net_if_stats()
    network_info = {}
    for interface, addrs in ip_info.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4
                network_info['IP'] = addr.address
            elif addr.family == socket.AF_PACKET:  # MAC
                network_info['MAC'] = addr.address
    return network_info

def get_logged_in_users():
    users = psutil.users()
    logged_in_users = [f"{user.name} (tty: {user.terminal})" for user in users]
    return logged_in_users

def explain_vulnerabilities(weak_passwords, insecure_files):
    explanation = ""
    if weak_passwords:
        explanation += "Vulnerabilidades encontradas:\n"
        explanation += "Usuários com senhas fracas podem ser explorados por ataques de força bruta.\n"
    
    if insecure_files:
        explanation += "Arquivos com permissões inseguras podem ser acessados por usuários não autorizados,\n"
        explanation += "permitindo que invasores leiam ou modifiquem dados críticos.\n"

    return explanation if explanation else "Nenhuma vulnerabilidade encontrada."

def run_security_check(text_edit):
    updates_status = check_for_updates()
    weak_passwords = check_weak_passwords()
    insecure_files = check_file_permissions()
    full_access_users = get_users_with_full_access()
    open_ports = get_open_ports()
    network_info = get_network_info()
    logged_in_users = get_logged_in_users()

    result = "Resultado da Verificação de Vulnerabilidades:\n"
    result += updates_status + "\n"
    
    if weak_passwords:
        result += "Usuários com senhas em texto claro: " + ", ".join(weak_passwords) + "\n"
    else:
        result += "Nenhum usuário com senhas fracas encontrado.\n"

    if insecure_files:
        result += "Arquivos com permissões inseguras: " + ", ".join(insecure_files) + "\n"
    else:
        result += "Nenhum arquivo com permissões inseguras encontrado.\n"

    if full_access_users:
        result += "Usuários com acesso total: " + ", ".join(full_access_users) + "\n"
    else:
        result += "Nenhum usuário com acesso total encontrado.\n"

    result += "\nPortas abertas: " + ", ".join(map(str, open_ports)) + "\n"
    result += "Endereço IP: " + network_info.get('IP', 'Não encontrado') + "\n"
    result += "Endereço MAC: " + network_info.get('MAC', 'Não encontrado') + "\n"
    result += "Usuários logados: " + ", ".join(logged_in_users) + "\n"

    # Explicação das vulnerabilidades
    vulnerabilities_explanation = explain_vulnerabilities(weak_passwords, insecure_files)
    result += "\n" + vulnerabilities_explanation

    text_edit.setPlainText(result)

class SecurityScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Scanner de Segurança')
        layout = QVBoxLayout()

        self.text_edit = QTextEdit(self)
        layout.addWidget(self.text_edit)

        scan_button = QPushButton('Executar Scan', self)
        scan_button.clicked.connect(lambda: run_security_check(self.text_edit))
        layout.addWidget(scan_button)

        self.setLayout(layout)
        self.resize(800, 600)

if __name__ == '__main__':
    app = QApplication([])
    scanner = SecurityScanner()
    scanner.show()
    app.exec_()