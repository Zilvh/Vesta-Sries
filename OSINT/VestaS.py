# Enhanced Port Scanner with additional features
import socket
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, IntPrompt, Confirm
from tqdm import tqdm
import argparse
import json
import csv
import time
from datetime import datetime
import threading

console = Console()

# Dictionary of common services for port identification
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 27017: "MongoDB", 8080: "HTTP-Alt", 9200: "Elasticsearch"
}

class PortScanner:
    def __init__(self):
        self.results = []
        self.start_time = None
        self.end_time = None
        
    def banner_grab(self, host, port, timeout=2):
        """Attempt to grab service banner"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            return banner[:100] if banner else "No banner"
        except:
            return "No banner"

    def scan_port(self, host, port, grab_banner=False):
        """Enhanced port scanning with optional banner grabbing"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            s.close()
            
            if result == 0:  # Port is open
                service = COMMON_SERVICES.get(port, "Unknown")
                banner = self.banner_grab(host, port) if grab_banner else "Not captured"
                return {
                    'port': port,
                    'service': service,
                    'banner': banner,
                    'status': 'Open'
                }
        except:
            pass
        return None

    def scan_range(self, host, start_port=1, end_port=1024, max_workers=100, grab_banner=False):
        """Scan a range of ports"""
        self.start_time = datetime.now()
        open_ports = []
        
        console.print(Panel(f"[bold cyan]🔍 Scanning {host} | Ports: {start_port}-{end_port} | Workers: {max_workers}[/bold cyan]"))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Scanning ports...", total=end_port-start_port+1)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self.scan_port, host, p, grab_banner): p 
                    for p in range(start_port, end_port + 1)
                }
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                    progress.advance(task)
        
        self.end_time = datetime.now()
        self.results = sorted(open_ports, key=lambda x: x['port'])
        return self.results

    def display_results(self):
        """Display results in a formatted table"""
        if not self.results:
            console.print("[red]❌ No open ports found[/red]")
            return
        
        table = Table(title="🚪 Open Ports Discovery")
        table.add_column("Port", justify="center", style="cyan")
        table.add_column("Service", justify="left", style="green")
        table.add_column("Status", justify="center", style="bold green")
        table.add_column("Banner", justify="left", style="yellow", max_width=40)
        
        for result in self.results:
            table.add_row(
                str(result['port']),
                result['service'],
                result['status'],
                result['banner'][:40] + "..." if len(result['banner']) > 40 else result['banner']
            )
        
        console.print(table)
        
        # Summary
        scan_time = (self.end_time - self.start_time).total_seconds()
        console.print(f"\n[bold green]✅ Found {len(self.results)} open ports in {scan_time:.2f} seconds[/bold green]")

    def save_results(self, filename, format_type="json"):
        """Save results to file in different formats"""
        if not self.results:
            console.print("[red]No results to save[/red]")
            return
        
        try:
            if format_type.lower() == "json":
                with open(filename, 'w') as f:
                    json.dump({
                        'scan_time': self.start_time.isoformat(),
                        'duration': (self.end_time - self.start_time).total_seconds(),
                        'results': self.results
                    }, f, indent=2)
            
            elif format_type.lower() == "csv":
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['port', 'service', 'status', 'banner'])
                    writer.writeheader()
                    writer.writerows(self.results)
            
            console.print(f"[green]💾 Results saved to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Error saving file: {e}[/red]")

def get_scan_options():
    """Interactive menu for scan options"""
    console.print(Panel("[bold yellow]🛠️  Port Scanner Configuration[/bold yellow]"))
    
    target = Prompt.ask("🎯 Enter IP address or domain")
    
    # Port range selection
    console.print("\n[cyan]📋 Select port range:[/cyan]")
    console.print("1. Quick scan (1-1024)")
    console.print("2. Extended scan (1-65535)")
    console.print("3. Custom range")
    console.print("4. Specific ports")
    
    choice = IntPrompt.ask("Choose option", choices=["1", "2", "3", "4"], default=1)
    
    if choice == 1:
        start_port, end_port = 1, 1024
    elif choice == 2:
        start_port, end_port = 1, 65535
    elif choice == 3:
        start_port = IntPrompt.ask("Start port", default=1)
        end_port = IntPrompt.ask("End port", default=1024)
    else:  # choice == 4
        ports_input = Prompt.ask("Enter ports (comma-separated, e.g., 22,80,443)")
        specific_ports = [int(p.strip()) for p in ports_input.split(',')]
        return target, specific_ports, None, None
    
    # Advanced options
    max_workers = IntPrompt.ask("🔧 Number of threads", default=100)
    grab_banner = Confirm.ask("🏷️  Grab service banners?", default=False)
    
    return target, None, (start_port, end_port), {'max_workers': max_workers, 'grab_banner': grab_banner}

def scan_specific_ports(scanner, host, ports, **kwargs):
    """Scan specific ports"""
    scanner.start_time = datetime.now()
    results = []
    
    console.print(Panel(f"[bold cyan]🔍 Scanning specific ports on {host}[/bold cyan]"))
    
    with Progress() as progress:
        task = progress.add_task("Scanning ports...", total=len(ports))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=kwargs.get('max_workers', 50)) as executor:
            futures = {
                executor.submit(scanner.scan_port, host, p, kwargs.get('grab_banner', False)): p 
                for p in ports
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                progress.advance(task)
    
    scanner.end_time = datetime.now()
    scanner.results = sorted(results, key=lambda x: x['port'])
    return scanner.results

def main():
    console.print(Panel.fit("[bold blue]🚀 Enhanced Port Scanner v2.0[/bold blue]", border_style="blue"))
    
    # Interactive mode
    target, specific_ports, port_range, options = get_scan_options()
    
    scanner = PortScanner()
    
    try:
        if specific_ports:
            scan_specific_ports(scanner, target, specific_ports, **options)
        else:
            start_port, end_port = port_range
            scanner.scan_range(target, start_port, end_port, **options)
        
        # Display results
        scanner.display_results()
        
        # Option to save results
        if scanner.results and Confirm.ask("\n💾 Save results to file?", default=False):
            filename = Prompt.ask("📁 Enter filename", default=f"scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            format_choice = Prompt.ask("📄 Choose format", choices=["json", "csv"], default="json")
            
            if not filename.endswith(f".{format_choice}"):
                filename += f".{format_choice}"
            
            scanner.save_results(filename, format_choice)
        
    except KeyboardInterrupt:
        console.print("\n[red]⚠️  Scan interrupted by user[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")

if __name__ == "__main__":
    main()
