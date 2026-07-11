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
        print("[!] This script must be run as root.")
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

# Import Masscan after possible installation
try:
    import masscan
    HAS_MASSCAN_LIB = True
except ImportError:
    HAS_MASSCAN_LIB = False


# ==========================================
# CONFIGURATION
# ==========================================
CLOUD_IP_RANGE_CIDR = "52.0.0.0/14"   # e.g. AWS CloudFront / EC2

PORT = 443
TIMEOUT = 1.0
CONCURRENCY_LIMIT_STATEFUL = 1000
MASSCAN_ARGS = '--max-rate 50000 --wait 1'

STATEFUL_IP_COUNT = 1_000
MASSCAN_IP_COUNT  = 100_000


# ==========================================
# 1. BUILD IP LIST FROM CIDR
# ==========================================
def get_target_ips():
    try:
        network = ipaddress.IPv4Network(CLOUD_IP_RANGE_CIDR, strict=False)
        ips = [str(ip) for ip in network.hosts()]
        print(f"CIDR {CLOUD_IP_RANGE_CIDR} expanded to {len(ips)} host IPs")
        return ips
    except Exception as e:
        print(f"Error parsing CIDR: {e}")
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
# 3. STATELESS SCAN (Masscan) – with result file
# ==========================================
def run_masscan_scan(ips):
    if not HAS_MASSCAN_LIB:
        print("[!] 'python-masscan' not installed. Skipping Masscan.")
        return None, None
    if os.geteuid() != 0:
        print("[!] Masscan requires root.")
        return None, None

    try:
        mas = masscan.PortScanner()
    except Exception:
        print("[!] Masscan binary not found.")
        return None, None

    # Write the IP list to a temporary file (required for large lists)
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='_targets.txt') as tmp:
            tmp.write('\n'.join(ips))
            ip_file = tmp.name
        print(f"[*] Masscan target list: {ip_file}")
    except Exception as e:
        print(f"[!] Failed to write target file: {e}")
        return None, None

    open_count = 0
    result_file = None

    try:
        mas.scan(hosts='', ports=str(PORT), arguments=f'{MASSCAN_ARGS} -iL {ip_file}')
        open_hosts = mas.all_hosts         # list of IPs with the port open
        open_count = len(open_hosts)

        # Save the open hosts to a separate temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='_masscan_results.txt') as res_f:
            res_f.write('\n'.join(open_hosts))
            result_file = res_f.name
        print(f"[*] Masscan results (open IPs): {result_file}")

    except Exception as e:
        print(f"[!] Masscan run failed: {e}")
        open_count = 0
        result_file = None
    finally:
        try:
            os.unlink(ip_file)      # delete the target list
        except Exception:
            pass

    return open_count, result_file


# ==========================================
# 4. MAIN
# ==========================================
def main():
    setup()
    all_ips = get_target_ips()
    total = len(all_ips)

    if total < STATEFUL_IP_COUNT or total < MASSCAN_IP_COUNT:
        print(f"Not enough IPs. Need at least {max(STATEFUL_IP_COUNT, MASSCAN_IP_COUNT)}.")
        sys.exit(1)

    stateful_ips = all_ips[:STATEFUL_IP_COUNT]
    masscan_ips  = all_ips[:MASSCAN_IP_COUNT]

    print(f"\nStateful scan: {len(stateful_ips)} IPs")
    print(f"Masscan: {len(masscan_ips)} IPs\n")

    # Stateful
    print("Running stateful async scan...")
    start = time.time()
    stateful_open = asyncio.run(run_stateful_scan(stateful_ips))
    stateful_time = time.time() - start
    print("Stateful scan done.\n")

    # Masscan
    print("Running Masscan...")
    start = time.time()
    masscan_open, result_file = run_masscan_scan(masscan_ips)
    masscan_time = time.time() - start if masscan_open is not None else None
    if masscan_open is not None:
        print("Masscan done.\n")
        if result_file:
            print(f"You can view the raw results with:  cat {result_file}\n")

    # Summary
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
