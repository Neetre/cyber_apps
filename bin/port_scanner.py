import os
import socket
import threading
import concurrent.futures
from dotenv import load_dotenv
import colorama
from colorama import Fore
colorama.init()

load_dotenv()

print_lock = threading.Lock()
IP = os.environ.get("IP")


def scan(ip, port):
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(1)
    try:
        scanner.connect((ip, port))
        scanner.close()
        with print_lock:
            print(Fore.WHITE + f"[{port}]" + Fore.GREEN + "Opened")
    except Exception as e:
        pass
    

def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1000):
            executor.submit(scan, IP, port + 1)
            

if __name__ == "__main__":
    main()
