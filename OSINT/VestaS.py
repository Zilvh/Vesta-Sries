import socket
import concurrent.futures
from rich.console import Console
from tqdm import tqdm

console = Console()

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((host, port))
        s.close()
        return port
    except:
        return None

def main():
    target = input("Masukkan IP atau domain: ").strip()
    open_ports = []

    console.print(f"[bold cyan]Scanning {target}...[/bold cyan]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target, p): p for p in range(1, 1025)}
        for future in tqdm(concurrent.futures.as_completed(futures), total=1024):
            port = future.result()
            if port:
                open_ports.append(port)
    console.print(f"[green]Open ports: {open_ports}[/green]")

if __name__ == "__main__":
    main()


