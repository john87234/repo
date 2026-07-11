import asyncio
import time
import sys
import os
import ipaddress
import tempfile

# Masscan wrapper
try:
    import masscan
    HAS_MASSCAN_LIB = True
except ImportError:
    HAS_MASSCAN_LIB = False

# ==========================================
# CONFIGURATION
# ==========================================
# Large cloud CIDR – a /14 contains ~262k usable IPs, enough for both scans.
CLOUD_IP_RANGE_CIDR = "52.0.0.0/14"   # AWS us-east-1 sample prefix

PORT = 443
TIMEOUT = 1.0
CONCURRENCY_LIMIT_STATEFUL = 1000     # 1,000 concurrent async connections
MASSCAN_ARGS = '--max-rate 50000 --wait 1'

# Number of IPs to use for each scan method
STATEFUL_IP_COUNT = 1_000
MASSCAN_IP_COUNT  = 100_000


# ==========================================
# 0. BUILD IP LIST FROM CLOUD CIDR
# ==========================================
def get_target_ips():
    """Expand the configured CIDR into a list of IP addresses."""
    try:
        network = ipaddress.IPv4Network(CLOUD_IP_RANGE_CIDR, strict=False)
        # Host addresses only (exclude network & broadcast)
        ips = [str(ip) for ip in network.hosts()]
        print(f"CIDR {CLOUD_IP_RANGE_CIDR} expanded to {len(ips)} host IPs")
        return ips
    except Exception as e:
        print(f"Error parsing CIDR {CLOUD_IP_RANGE_CIDR}: {e}")
        sys.exit(1)


# ==========================================
# 1. STATEFUL SCAN (Async TCP Connect)
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
# 2. STATELESS SCAN (Masscan via temp file)
# ==========================================
def run_masscan_scan(ips):
    if not HAS_MASSCAN_LIB:
        print("[!] 'python-masscan' not installed. Skipping Masscan.")
        return None
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[!] Masscan requires root privileges. Skipping...")
        return None

    try:
        mas = masscan.PortScanner()
    except Exception:
        print("[!] Masscan binary not found. Skipping...")
        return None

    # Write all IPs to a temporary file to avoid "Argument list too long"
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
            tmp.write('\n'.join(ips))
            ip_file = tmp.name
    except Exception as e:
        print(f"[!] Failed to write IP list to temp file: {e}")
        return None

    try:
        # Use -iL to load targets from file; hosts left empty
        mas.scan(
            hosts='',                           # no inline targets
            ports=str(PORT),
            arguments=f'{MASSCAN_ARGS} -iL {ip_file}'
        )
        open_count = len(mas.all_hosts)
    except Exception as e:
        print(f"[!] Masscan run failed: {e}")
        open_count = None
    finally:
        try:
            os.unlink(ip_file)                  # delete the temporary file
        except Exception:
            pass

    return open_count


# ==========================================
# 3. MAIN RUNNER
# ==========================================
def main():
    all_ips = get_target_ips()
    total_available = len(all_ips)

    if total_available < STATEFUL_IP_COUNT:
        print(f"Only {total_available} IPs available – cannot run {STATEFUL_IP_COUNT} for stateful scan.")
        sys.exit(1)
    if total_available < MASSCAN_IP_COUNT:
        print(f"Only {total_available} IPs available – cannot run {MASSCAN_IP_COUNT} for Masscan.")
        sys.exit(1)

    # Slice the IP list for each scan method
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
