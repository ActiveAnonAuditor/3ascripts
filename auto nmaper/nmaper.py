#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import time
import requests
from platform import system
from colorama import init, Fore

init(autoreset=True)

TMP_DIR = "tmp"
if not os.path.isdir(TMP_DIR):
    os.makedirs(TMP_DIR)

def perevirta_ta_vstanovy_paket(package_name):
    try:
        __import__(package_name)
        print(Fore.GREEN + f"[✓] Пакет '{package_name}' вже встановлено.")
    except ImportError:
        print(Fore.YELLOW + f"[!] Пакет '{package_name}' не знайдено. Встановлюю...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(Fore.GREEN + f"[✓] Пакет '{package_name}' встановлено.")

def vstanovyty_linux_instrument(instrument_name):
    pkg_manager = None
    if shutil.which("apt-get"):
        pkg_manager = "apt-get"
    elif shutil.which("dnf"):
        pkg_manager = "dnf"
    elif shutil.which("yum"):
        pkg_manager = "yum"
    elif shutil.which("pacman"):
        pkg_manager = "pacman"
    else:
        print(Fore.RED + "[!] Невідомий пакетний менеджер. Не вдалося встановити автоматично.")
        return False
    print(Fore.YELLOW + f"[!] Спроба встановити '{instrument_name}' за допомогою {pkg_manager}...")
    try:
        if pkg_manager == "apt-get":
            subprocess.check_call(["sudo", "apt-get", "update"])
            subprocess.check_call(["sudo", "apt-get", "install", "-y", instrument_name])
        elif pkg_manager == "dnf":
            subprocess.check_call(["sudo", "dnf", "install", "-y", instrument_name])
        elif pkg_manager == "yum":
            subprocess.check_call(["sudo", "yum", "install", "-y", instrument_name])
        elif pkg_manager == "pacman":
            subprocess.check_call(["sudo", "pacman", "-Sy", instrument_name, "--noconfirm"])
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[!] Помилка встановлення '{instrument_name}': {e}")
        return False
    if shutil.which(instrument_name):
        print(Fore.GREEN + f"[✓] '{instrument_name}' успішно встановлено.")
        return True
    else:
        print(Fore.RED + f"[!] Не вдалося встановити '{instrument_name}'.")
        return False

def pereviryty_ta_vstanovyty_instrument(instrument_name):
    if shutil.which(instrument_name) is None:
        print(Fore.RED + f"[!] Утиліту '{instrument_name}' не знайдено в системі.")
        if system() == "Linux":
            success = vstanovyty_linux_instrument(instrument_name)
            if not success:
                print(Fore.RED + f"[!] Автоматичне встановлення '{instrument_name}' не вдалося.")
                sys.exit(1)
        else:
            print(Fore.YELLOW + f"Будь ласка, встановіть '{instrument_name}' вручну.")
            sys.exit(1)
    else:
        print(Fore.GREEN + f"[✓] '{instrument_name}' виявлено в системі.")

print(Fore.BLUE + "\nПеревірка встановлених бібліотек та інструментів...\n")
perevirta_ta_vstanovy_paket("python-nmap")
perevirta_ta_vstanovy_paket("colorama")

pereviryty_ta_vstanovyty_instrument("nmap")
pereviryty_ta_vstanovyty_instrument("xsltproc")

try:
    import nmap
except ImportError:
    print(Fore.RED + "Помилка імпорту бібліотеки python-nmap.")
    sys.exit(1)

LIVE = True
scanner = nmap.PortScanner()

def ochystyty_ekran():
    if system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

def skachaty_xsl():
    xsl_path = os.path.join(TMP_DIR, "nmap-bootstrap.xsl")
    if not os.path.isfile(xsl_path):
        print(Fore.YELLOW + "[!] nmap-bootstrap.xsl не знайдено. Завантажую...")
        url = "https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl"
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            with open(xsl_path, "wb") as xsl_file:
                xsl_file.write(resp.content)
            print(Fore.GREEN + "[✓] Завантажено nmap-bootstrap.xsl.")
        except Exception as e:
            print(Fore.RED + f"[!] Неможливо завантажити nmap-bootstrap.xsl: {e}")
            sys.exit(1)

def konvertyvaty_v_html(xml_file, html_file):
    xsl_path = os.path.join(TMP_DIR, "nmap-bootstrap.xsl")
    if not os.path.isfile(xsl_path):
        skachaty_xsl()
    cmd = f"xsltproc -o {html_file} {xsl_path} {xml_file}"
    try:
        subprocess.check_call(cmd, shell=True)
        print(Fore.GREEN + f"[✓] {xml_file} → {html_file}")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[!] Помилка конвертації {xml_file} у HTML: {e}")

def otrymaty_vidkryti_porty(xml_file):
    local_scan = nmap.PortScanner()
    with open(xml_file, "r", encoding="utf-8") as fd:
        xml_data = fd.read()
    local_scan.analyse_nmap_xml_scan(xml_data)
    open_ports = set()
    for host in local_scan.all_hosts():
        for proto in local_scan[host].all_protocols():
            for port, port_data in local_scan[host][proto].items():
                if port_data["state"] == "open":
                    open_ports.add(str(port))
    return open_ports

ochystyty_ekran()

print(Fore.GREEN + r"""
  ______               __                      __    __
 /      \             |  \                    |  \  |  \
|  $$$$$$\ __    __  _| $$_     ______        | $$\ | $$ ______ ____    ______    ______            ______    ______
| $$__| $$|  \  |  \|   $$ \   /      \       | $$$\| $$|      \    \  |      \  /      \  ______  /      \  /      \
| $$    $$| $$  | $$ \$$$$$$  |  $$$$$$\      | $$$$\ $$| $$$$$$\$$$$\  \$$$$$$\|  $$$$$$\|      \|  $$$$$$\|  $$$$$$\
| $$$$$$$$| $$  | $$  | $$ __ | $$  | $$      | $$\$$ $$| $$ | $$ | $$ /      $$| $$  | $$ \$$$$$$| $$    $$| $$   \$$
| $$  | $$| $$__/ $$  | $$|  \| $$__/ $$      | $$ \$$$$| $$ | $$ | $$|  $$$$$$$| $$__/ $$        | $$$$$$$$| $$
| $$  | $$ \$$    $$   \$$  $$ \$$    $$      | $$  \$$$| $$ | $$ | $$ \$$    $$| $$    $$         \$$     \| $$
 \$$   \$$  \$$$$$$     \$$$$   \$$$$$$        \$$   \$$ \$$  \$$  \$$  \$$$$$$$| $$$$$$$           \$$$$$$$ \$$
                                                                                | $$
                                                                                | $$
""",
Fore.BLUE + r"""                                                            \$$
$$\                        $$$$$$\                      $$\ $$\ $$\
$$ |                      $$  __$$\                     \__|$$ |\__|
$$$$$$$\  $$\   $$\       $$ /  $$ |$$\   $$\ $$\   $$\ $$\ $$ |$$\ $$\   $$\ $$$$$$\$$$$\
$$  __$$\ $$ |  $$ |      $$$$$$$$ |$$ |  $$ |\$$\ $$  |$$ |$$ |$$ |$$ |  $$ |$$  _$$  _$$\
$$ |  $$ |$$ |  $$ |      $$  __$$ |$$ |  $$ | \$$$$  / $$ |$$ |$$ |$$ |  $$ |$$ / $$ / $$ |
$$ |  $$ |$$ |  $$ |      $$ |  $$ |$$ |  $$ | $$  $$<  $$ |$$ |$$ |$$ |  $$ |$$ | $$ | $$ |
$$$$$$$  |\$$$$$$$ |      $$ |  $$ |\$$$$$$  |$$  /\$$\ $$ |$$ |$$ |\$$$$$$  |$$ | $$ | $$ |
\_______/  \____$$ |      \__|  \__| \______/ \__/  \__|\__|\__|\__| \______/ \__| \__| \__|
          $$\   $$ |
          \$$$$$$  |                                                             v0.1
           \______/
""")

time.sleep(3)
ochystyty_ekran()

print(Fore.BLUE + '''
██████╗ ███████╗██╗   ██╗███████╗██╗      ██████╗ ██████╗ ███████╗██████╗     ███████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██║   ██║██╔════╝██║     ██╔═══██╗██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔═══██╗██╔══██╗
██║  ██║█████╗  ██║   ██║█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ██║    █████╗  ██║   ██║██████╔╝
██║  ██║██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║     ██║   ██║██╔═══╝ ██╔══╝  ██║  ██║    ██╔══╝  ██║   ██║██╔══██╗
██████╔╝███████╗ ╚████╔╝ ███████╗███████╗╚██████╔╝██║     ███████╗██████╔╝    ██║     ╚██████╔╝██║  ██║
╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═════╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝

''' , Fore.YELLOW +'''


         .8.                   .8.                   .8.
        .888.                 .888.                 .888.
       :88888.               :88888.               :88888.
      . `88888.             . `88888.             . `88888.
     .8. `88888.           .8. `88888.           .8. `88888.
    .8`8. `88888.         .8`8. `88888.         .8`8. `88888.
   .8' `8. `88888.       .8' `8. `88888.       .8' `8. `88888.
  .8'   `8. `88888.     .8'   `8. `88888.     .8'   `8. `88888.
 .888888888. `88888.   .888888888. `88888.   .888888888. `88888.
.8'       `8. `88888. .8'       `8. `88888. .8'       `8. `88888.

''')
time.sleep(3)
ochystyty_ekran()
while LIVE:
    print(Fore.BLUE + "Напишіть ", Fore.GREEN + 'auto', Fore.BLUE + 'або введіть звичайну команду nmap:')
    user_input = input(Fore.GREEN + ">>: ")

    if user_input.startswith('nmap'):
        os.system(user_input)
    elif user_input.startswith('auto'):
        targets_file = input(Fore.GREEN + "Введіть шлях до файлу зі списком цілей: ").strip()

        print(Fore.YELLOW + "\n[Fast TCP] Виконується перший етап сканування...")
        fast_cmd = f"nmap -T4 -Pn -p- -v -iL {targets_file} -oX tmp/FastTCPscan.xml"
        print(Fore.CYAN + f"[CMD] {fast_cmd}")
        os.system(fast_cmd)
        konvertyvaty_v_html("tmp/FastTCPscan.xml", "tmp/FastTCPscan.html")

        open_ports = otrymaty_vidkryti_porty("tmp/FastTCPscan.xml")
        ports_str = ",".join(sorted(open_ports)) if open_ports else ""

        if ports_str:
            print(Fore.YELLOW + "\n[Service Detection] Виконується другий етап сканування...")
            service_cmd = f"nmap -Pn -sV -sC -v -p {ports_str} -iL {targets_file} -oX tmp/ServiceTCPscan.xml"
            print(Fore.CYAN + f"[CMD] {service_cmd}")
            os.system(service_cmd)
            konvertyvaty_v_html("tmp/ServiceTCPscan.xml", "tmp/ServiceTCPscan.html")
        else:
            print(Fore.RED + "\nВідкриті порти не знайдено на першому етапі.")

        print(Fore.YELLOW + "\n[UDP Scan] Виконується третій етап сканування...")
        udp_cmd = f"nmap -sU -F -Pn -vv -n -iL {targets_file} -oX tmp/UDPPortsReport.xml"
        print(Fore.CYAN + f"[CMD] {udp_cmd}")
        os.system(udp_cmd)
        konvertyvaty_v_html("tmp/UDPPortsReport.xml", "tmp/UDPPortsReport.html")

        print(Fore.GREEN + "\nТриетапне сканування завершено!\n")
    elif user_input.startswith('exit') or user_input.startswith('quit'):
        LIVE = False
    else:
        print(Fore.RED + "Неправильне значення. Спробуйте ще раз.")