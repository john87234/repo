import asyncio
import time
import sys
import os
import subprocess
import ipaddress
import tempfile

# ==========================================
# 0. SETUP – ensure required packages are installed
# ==========================================
def setup():
    """Install required system and Python packages."""
    if os.geteuid() != 0:
        print("[!] This script must be run as root to install packages and run Masscan.")
        sys.exit(1)

    print("[*] Updating package list and installing dependencies...")
    try:
        subprocess.run(['apt', 'update'], check=True)
        subprocess.run(
            ['apt', 'install', '-y', 'python3-pip', 'python3-dev', 'build-essential', 'masscan'],
            check=True
        )
        subprocess.run(['pip3', 'install', 'scapy', 'python-masscan'], check=True)
        print("[*] All dependencies installed.\n")
    except subprocess.CalledProcessError as e:
        print(f"[!] Setup failed: {e}")
        sys.exit(1)

# Now import Masscan after installation (it may have just been installed)
try:
    import masscan
    HAS_MASSCAN_LIB = True
except ImportError:
    HAS_MASSCAN_LIB = False


# ==========================================
# CONFIGURATION
# ==========================================
CLOUD_IP_RANGE_CIDR = "52.0.0.0/14"   # AWS us-east-1 sample prefix

PORT = 443
TIMEOUT = 1.0
CONCURRENCY_LIMIT_STATEFUL = 1000     # 1,000 concurrent async connections
MASSCAN_ARGS = '--max-rate 50000 --wait 1'

STATEFUL_IP_COUNT = 1_000
MASSCAN_IP_COUNT  = 100_000


# ==========================================
# 1. BUILD IP LIST FROM CLOUD CIDR
# ==========================================
def get_target_ips():
    try:
        network = ipaddress.IPv4Network(CLOUD_IP_RANGE_CIDR, strict=False)
        ips = [str(ip) for ip in network.hosts()]
        print(f"CIDR {CLOUD_IP_RANGE_CIDR} expanded to {len(ips)} host IPs")
        return ips
    except Exception as e:
        print(f"Error parsing CIDR {CLOUD_IP_RANGE_CIDR}: {e}")
        sys.exit(1)


# ==========================================
# 2. STATEFUL SCAN (Async TCP Connect)
# ==========================================
async def stateful_scan_ip(sem, ip):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, PORT), timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

async def run_stateful_scan(ips):
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT_STATEFUL)
    tasks = [stateful_scan_ip(sem, ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    return sum(1 for is_open in results if is_open)


# ==========================================
# 3. STATELESS SCAN (Masscan via temp file)
# ==========================================
def run_masscan_scan(ips):
    if not HAS_MASSCAN_LIB:
        print("[!] 'python-masscan' not installed. Skipping Masscan.")
        return None
    if os.geteuid() != 0:
        print("[!] Masscan requires root privileges. Skipping...")
        return None

    try:
        mas = masscan.PortScanner()
    except Exception:
        print("[!] Masscan binary not found. Skipping...")
        return None

    # Write IPs to a temporary file and show its path
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
            tmp.write('\n'.join(ips))
            ip_file = tmp.name
        print(f"[*] Masscan target list written to: {ip_file}")
    except Exception as e:
        print(f"[!] Failed to write IP list to temp file: {e}")
        return None

    try:
        mas.scan(
            hosts='',
            ports=str(PORT),
            arguments=f'{MASSCAN_ARGS} -iL {ip_file}'
        )
        open_count = len(mas.all_hosts)
    except Exception as e:
        print(f"[!] Masscan run failed: {e}")
        open_count = None
    finally:
        try:
            os.unlink(ip_file)   # clean up
        except Exception:
            pass

    return open_count


# ==========================================
# 4. MAIN RUNNER
# ==========================================
def main():
    # Run setup first (will exit if not root or if install fails)
    setup()

    all_ips = get_target_ips()
    total_available = len(all_ips)

    if total_available < STATEFUL_IP_COUNT:
        print(f"Only {total_available} IPs available – need {STATEFUL_IP_COUNT} for stateful scan.")
        sys.exit(1)
    if total_available < MASSCAN_IP_COUNT:
        print(f"Only {total_available} IPs available – need {MASSCAN_IP_COUNT} for Masscan.")
        sys.exit(1)

    stateful_ips = all_ips[:STATEFUL_IP_COUNT]
    masscan_ips  = all_ips[:MASSCAN_IP_COUNT]

    print(f"\nStateful scan will use {len(stateful_ips)} IPs")
    print(f"Masscan will use {len(masscan_ips)} IPs\n")

    # --- Stateful Scan ---
    print("Running stateful async TCP connect scan...")
    start = time.time()
    stateful_open = asyncio.run(run_stateful_scan(stateful_ips))
    stateful_time = time.time() - start
    print("Stateful scan done.\n")

    # --- Masscan ---
    print("Running stateless Masscan...")
    start = time.time()
    masscan_open = run_masscan_scan(masscan_ips)
    masscan_time = time.time() - start if masscan_open is not None else None
    if masscan_open is not None:
        print("Masscan done.\n")

    # --- Summary ---
    print("=" * 60)
    print(f"{'SCAN TYPE':<25} | {'OPEN PORTS':<12} | {'TIME (s)':<10}")
    print("-" * 60)
    print(f"{'Stateful (Async) 1k IPs':<25} | {stateful_open:<12} | {stateful_time:<10.2f}")
    if masscan_open is not None:
        print(f"{'Stateless (Masscan) 100k IPs':<25} | {masscan_open:<12} | {masscan_time:<10.2f}")
    else:
        print(f"{'Stateless (Masscan)':<25} | {'Skipped':<12} | {'N/A':<10}")
    print("=" * 60)

if __name__ == "__main__":
    main()
