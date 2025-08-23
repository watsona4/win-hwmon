
import os, sys, runpy, traceback, datetime
from pathlib import Path  # <-- missing before; needed for run_target()

# Force unbuffered so services don't swallow partial lines
os.environ.setdefault("PYTHONUNBUFFERED", "1")
# Encourage Python to dump tracebacks on faults
os.environ.setdefault("PYTHONFAULTHANDLER", "1")

# Optional extra log file (in addition to service wrapper logs)
LAUNCHER_LOG = os.getenv("LAUNCHER_LOG", "").strip()

def log(msg: str):
    line = f"[{datetime.datetime.now().isoformat(timespec='seconds')}] {msg}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    if LAUNCHER_LOG:
        try:
            with open(LAUNCHER_LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

try:
    import faulthandler
    faulthandler.enable(file=sys.stderr, all_threads=True)
except Exception:
    pass

# ------- Configurable via env (optional) -------
LHM_SCHEME = os.getenv("LHM_SCHEME", "http")
LHM_PORT   = int(os.getenv("LHM_PORT", "8085"))
LHM_PATH   = os.getenv("LHM_PATH", "/data.json")
LHM_HOST   = os.getenv("LHM_HOST", "").strip()
TARGET_SCRIPT = os.getenv("TARGET_SCRIPT", "win_hwmon_mqtt.py")

def get_primary_ipv4():
    # WMI first
    try:
        import wmi  # type: ignore
        try:
            c = wmi.WMI()
            candidates = []
            for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                ips = getattr(nic, "IPAddress", None) or []
                gws = getattr(nic, "DefaultIPGateway", None) or []
                desc = (getattr(nic, "Description", "") or "").lower()
                if any(bad in desc for bad in ("loopback", "virtual", "vmware", "hyper-v", "tailscale", "bluetooth")):
                    continue
                ipv4s = [ip for ip in ips if ip and "." in ip and not ip.startswith("169.254.")]
                if not ipv4s:
                    continue
                score = 1 if gws else 0
                candidates.append((score, ipv4s[0]))
            if candidates:
                candidates.sort(reverse=True)
                return candidates[0][1]
        except Exception as e:
            log(f"WMI IPv4 failed: {e!r}")
    except Exception as e:
        log(f"Import wmi failed: {e!r}")

    # Socket fallback
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("169."):
            return ip
    except Exception as e:
        log(f"Socket IPv4 failed: {e!r}")
    return None

def ensure_lhm_urls():
    # Respect explicit configuration
    if os.getenv("LHM_URLS") or os.getenv("LHM_URL"):
        log(f"Using provided LHM_URLS/LHM_URL")
        return
    if LHM_HOST:
        url = f"{LHM_SCHEME}://{LHM_HOST}:{LHM_PORT}{LHM_PATH}"
        os.environ["LHM_URLS"] = url
        log(f"Built LHM_URLS from LHM_HOST: {url}")
        return
    ip = get_primary_ipv4()
    urls = []
    if ip:
        urls.append(f"{LHM_SCHEME}://{ip}:{LHM_PORT}{LHM_PATH}")
    urls.append(f"{LHM_SCHEME}://127.0.0.1:{LHM_PORT}{LHM_PATH}")
    os.environ["LHM_URLS"] = ",".join(urls)
    log(f"Auto LHM_URLS: {os.environ['LHM_URLS']}")

def run_target():
    here = Path(__file__).resolve().parent
    target = Path(TARGET_SCRIPT)
    if not target.is_absolute():
        target = (here / target).resolve()
    if not target.exists():
        log(f"Target not found: {target}")
        sys.exit(2)

    # Rebuild argv to mimic direct launch
    sys.argv = [str(target), *sys.argv[1:]]
    log(f"Launching target: {target} argv={sys.argv[1:]}")

    # Install a robust excepthook that writes into our log
    def _excepthook(exc_type, exc, tb):
        log("=== Uncaught exception ===")
        for line in traceback.format_exception(exc_type, exc, tb):
            for sub in line.rstrip('\n').splitlines():
                log(sub)
        log("=== End exception ===")
    sys.excepthook = _excepthook

    # Run
    try:
        runpy.run_path(str(target), run_name="__main__")
    except SystemExit as e:
        log(f"SystemExit: code={e.code}")
        raise
    except Exception:
        # Let excepthook handle details
        raise

if __name__ == "__main__":
    try:
        ensure_lhm_urls()
        run_target()
    except Exception:
        # Final guard: print full traceback via our logger
        log("=== Fatal exception in launcher ===")
        for line in traceback.format_exc().splitlines():
            log(line)
        log("=== End fatal exception ===")
        sys.exit(1)
