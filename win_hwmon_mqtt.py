#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
win_hwmon_mqtt.py (patched)
Windows hardware → MQTT exporter with Home Assistant Discovery.

Enhancements in this build:
- LHM_URLS support (comma-separated) with ordered failover.
- Optional auto-build of LHM_URLS from active IPv4 + 127.0.0.1 fallback.
- Uses WMI (best) or socket trick to find active IPv4.
- Paho-mqtt v2: no deprecated clean_session; Callback API v2 enabled.
- Extra imports, numeric parsing robustness, and logging polish.

Requirements:
  pip install psutil paho-mqtt requests colorlog wmi
Optional tools:
  - smartctl.exe (smartmontools for Windows) in PATH
  - LibreHardwareMonitor with web server enabled (http://host:8085) OR set LHM_URLS/LHM_URL
"""

import os
import re
import time
import json
import socket
import subprocess
import shutil
import argparse
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

# Third-party
import psutil
import requests

# ------------- Logging setup -------------
def setup_logger(level_name: str = "INFO"):
    """Create a colorlog logger if available, else std logging."""
    try:
        import colorlog  # type: ignore
        import logging
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
            }
        ))
        lg = colorlog.getLogger("win_hwmon")
        lg.handlers.clear()
        lg.addHandler(handler)
        lg.setLevel(getattr(logging, level_name.upper(), logging.INFO))
        return lg
    except Exception:
        import logging
        logging.basicConfig(
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            level=getattr(logging, level_name.upper(), logging.INFO),
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        return logging.getLogger("win_hwmon")


def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name, str(default)).strip().lower()
    return v in ("1", "true", "yes", "on")


def env_list(name: str) -> List[str]:
    return [s.strip() for s in os.getenv(name, "").split(",") if s.strip()]


# ------------- Config (env + CLI) -------------
HOSTNAME = socket.gethostname() or os.getenv("COMPUTERNAME", "windows")

# Default env
MQTT_HOST = os.getenv("MQTT_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")
MQTT_TLS = env_bool("MQTT_TLS", False)
MQTT_CLIENT_ID = os.getenv("MQTT_CLIENT_ID", f"win-hwmon-{HOSTNAME}")

BASE_TOPIC = os.getenv("BASE_TOPIC", f"winhw/{HOSTNAME}")
DISCOVERY_PREFIX = os.getenv("DISCOVERY_PREFIX", "homeassistant")
PUBLISH_INTERVAL = float(os.getenv("PUBLISH_INTERVAL", "10"))

DEVICE_NAME = os.getenv("DEVICE_NAME", HOSTNAME)
DEVICE_ID = os.getenv("DEVICE_ID", f"winhw_{HOSTNAME}")

FS_TYPES_INCLUDE = env_list("FS_TYPES_INCLUDE")  # e.g. "NTFS,ReFS"
MOUNT_EXCLUDES = [s.rstrip("\\") for s in env_list("MOUNT_EXCLUDES")]  # e.g. "A:\,B:\"

SMART_ENABLE = env_bool("SMART_ENABLE", True)
SMART_TIMEOUT = int(os.getenv("SMART_TIMEOUT", "12"))
SMART_DEVICES = env_list("SMART_DEVICES")  # e.g. "\\.\PhysicalDrive0,\\.\PhysicalDrive1"

# ---- LibreHardwareMonitor configuration ----
# Back-compat single URL (may be empty)
LHM_URL_SINGLE = os.getenv("LHM_URL", "").strip()
# Preferred: comma-separated list
LHM_URLS_ENV = env_list("LHM_URLS") or ([LHM_URL_SINGLE] if LHM_URL_SINGLE else [])
LHM_TIMEOUT = float(os.getenv("LHM_TIMEOUT", "2"))

# Optional builder knobs (used when neither LHM_URLS nor LHM_URL given)
LHM_SCHEME = os.getenv("LHM_SCHEME", "http")
LHM_PORT   = int(os.getenv("LHM_PORT", "8085"))
LHM_PATH   = os.getenv("LHM_PATH", "/data.json")
LHM_HOST   = os.getenv("LHM_HOST", "").strip()  # Force host if you want

try:
    import wmi  # type: ignore
    HAVE_WMI = True
except Exception:
    HAVE_WMI = False

import paho.mqtt.client as mqtt  # noqa: E402


# ------------- MQTT helpers -------------
def device_info() -> Dict[str, Any]:
    return {
        "identifiers": [DEVICE_ID],
        "name": DEVICE_NAME,
        "manufacturer": "Microsoft / OEM",
        "model": "Windows",
        "sw_version": "win-hwmon 1.2",
    }


def avail_topic() -> str:
    return f"{BASE_TOPIC}/availability"


def make_obj_id(*parts: str) -> str:
    out = "_".join(p.replace("\\", "_").replace("/", "_").replace(" ", "_").replace(".", "_") for p in parts if p)
    return "".join(ch for ch in out if ch.isalnum() or ch in "-_")


def disc_topic(component: str, object_id: str) -> str:
    return f"{DISCOVERY_PREFIX}/{component}/{DEVICE_ID}/{object_id}/config"


def bytes_to_gib(n: float) -> float:
    return round(n / (1024**3), 3)


def mqtt_client(logger) -> mqtt.Client:
    # v2 callback API; still speaking MQTT v3.1.1 by default
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=MQTT_CLIENT_ID,
        protocol=mqtt.MQTTv311,
        transport="tcp",
    )
    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD or None)
    if MQTT_TLS:
        client.tls_set()
        client.tls_insecure_set(False)
    client.will_set(avail_topic(), payload="offline", qos=1, retain=True)
    client.enable_logger(logger)
    return client


def pub_config(client: mqtt.Client, component: str, obj_id: str, name: str, state_topic: str,
               unit: Optional[str] = None, device_class: Optional[str] = None, state_class: Optional[str] = None,
               icon: Optional[str] = None, value_template: Optional[str] = None, extra: Optional[Dict[str, Any]] = None):
    payload = {
        "name": name,
        "unique_id": f"{DEVICE_ID}_{obj_id}",
        "state_topic": state_topic,
        "availability_topic": avail_topic(),
        "device": device_info(),
    }
    if unit:
        payload["unit_of_measurement"] = unit
    if device_class:
        payload["device_class"] = device_class
    if state_class:
        payload["state_class"] = state_class
    if icon:
        payload["icon"] = icon
    if value_template:
        payload["value_template"] = value_template
    if extra:
        payload.update(extra)
    client.publish(disc_topic(component, obj_id), json.dumps(payload), qos=1, retain=True)


def pub_bin_sensor(client: mqtt.Client, obj: str, name: str, st: str, icon: str = "mdi:check-circle"):
    pub_config(client, "binary_sensor", obj, name, st,
               extra={"payload_on": "1", "payload_off": "0", "entity_category": "diagnostic"}, icon=icon)


# ------------- Networking helpers for LHM auto-detect -------------
def _get_primary_ipv4(logger) -> Optional[str]:
    # Prefer WMI (gives correct adapter + default gateway awareness)
    try:
        import wmi  # type: ignore
        try:
            c = wmi.WMI()
            candidates = []
            for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                ips = getattr(nic, "IPAddress", None) or []
                gws = getattr(nic, "DefaultIPGateway", None) or []
                desc = (getattr(nic, "Description", "") or "").lower()
                if any(b in desc for b in ("loopback", "virtual", "vmware", "hyper-v", "tailscale", "bluetooth")):
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
            logger.debug(f"WMI IPv4 detect failed: {e}")
    except Exception:
        pass
    # Socket fallback: "poor man's" primary IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("169."):
            return ip
    except Exception as e:
        logger.debug(f"socket IPv4 detect failed: {e}")
    return None


def _build_lhm_urls(logger) -> List[str]:
    """
    Resolution order:
      1) If LHM_URLS provided (or legacy LHM_URL) -> use as-is
      2) Else if LHM_HOST provided -> build from host
      3) Else -> build from active IPv4 + loopback fallback
    """
    if LHM_URLS_ENV:
        return LHM_URLS_ENV
    urls = []
    if LHM_HOST:
        urls.append(f"{LHM_SCHEME}://{LHM_HOST}:{LHM_PORT}{LHM_PATH}")
        return urls
    ip = _get_primary_ipv4(logger)
    if ip:
        urls.append(f"{LHM_SCHEME}://{ip}:{LHM_PORT}{LHM_PATH}")
    urls.append(f"{LHM_SCHEME}://127.0.0.1:{LHM_PORT}{LHM_PATH}")
    return urls


# ------------- Temperatures / LHM JSON -------------
def _num_or_none(v):
    import math
    if isinstance(v, (int, float)):
        try:
            if math.isnan(v) or math.isinf(v):
                return None
        except Exception:
            pass
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if not s or s.lower().startswith('nan'):
            return None
        m = re.search(r'-?\d+(?:[\.,]\d+)?', s)
        if m:
            try:
                return float(m.group(0).replace(',', '.'))
            except Exception:
                return None
    return None


def _get_lhm_json(logger):
    urls = _build_lhm_urls(logger)
    last_err = None
    for url in urls:
        try:
            logger.debug(f"LHM GET {url} timeout={LHM_TIMEOUT}")
            r = requests.get(url, timeout=LHM_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            last_err = e
            logger.debug(f"LHM fetch failed for {url}: {e}")
    raise RuntimeError(f"All LHM URLs failed: {urls} last_error={last_err}")


def lhm_read_temps(logger) -> Dict[str, float]:
    """Read temps from LibreHardwareMonitor JSON; returns map of label->°C."""
    temps: Dict[str, float] = {}
    try:
        data = _get_lhm_json(logger)

        def walk(node):
            if not isinstance(node, dict):
                return
            if node.get("Type") == "Temperature":
                name = node.get("Text") or node.get("Name") or "temp"
                val = _num_or_none(node.get("Value"))
                if val is not None:
                    temps[str(name)] = float(val)
                    logger.debug(f"LHM temp: {name} = {val}°C")
            for ch in (node.get("Children", []) or []):
                walk(ch)
            for s in (node.get("Sensors", []) or []):
                walk(s)

        walk(data)
    except Exception as e:
        logger.warning(f"LHM fetch failed: {e}")
    return temps


# ----- LHM comprehensive extraction -----
def _extract_unit_token(s: str) -> Optional[str]:
    if not isinstance(s, str):
        return None
    s = s.strip()
    m = re.search(r"(°C|%|[kKmMgGtT]?B/s|[kKmMgGtT]?B|mWh|MHz|kHz|Hz)", s)
    return m.group(1) if m else None


def _convert_value_by_type(typ: str, raw_value: Any) -> Tuple[Optional[float], Optional[str]]:
    """Return (value, unit) normalized for HA when possible."""
    val = _num_or_none(raw_value)
    if val is None:
        return None, None
    unit = None
    if typ == "Temperature":
        return val, "°C"
    if typ == "Voltage":
        return val, "V"
    if typ == "Power":
        return val, "W"
    if typ == "Clock":
        return val, "MHz"
    if typ in ("Load", "Level"):
        return val, "%"
    if typ in ("Throughput",):
        unit_token = _extract_unit_token(str(raw_value)) or ""
        mult = 1.0
        u = unit_token.lower()
        if "kb/s" in u:
            mult = 1024.0
        elif "mb/s" in u:
            mult = 1024.0**2
        elif "gb/s" in u:
            mult = 1024.0**3
        elif "b/s" in u:
            mult = 1.0
        return val * mult, "B/s"
    if typ in ("Data", "SmallData", "Energy"):
        unit_token = _extract_unit_token(str(raw_value)) or ""
        u = unit_token.lower()
        if "wh" in u:
            return val / 1000.0, "Wh"
        mult = 1.0
        if u == "kb":
            mult = 1024.0
        elif u == "mb":
            mult = 1024.0**2
        elif u == "gb":
            mult = 1024.0**3
        elif u == "tb":
            mult = 1024.0**4
        return val * mult, "B"
    return val, None


def lhm_collect(logger, include_types: Optional[set] = None) -> List[Dict[str, Any]]:
    """Walk LHM JSON and collect all leaf sensors."""
    out: List[Dict[str, Any]] = []
    try:
        data = _get_lhm_json(logger)
    except Exception as e:
        logger.warning(f"LHM fetch failed in collect: {e}")
        return out

    wanted = include_types or {"Temperature","Voltage","Power","Clock","Load","Throughput","Data","SmallData","Level","Energy","Factor"}

    def walk(node, path_parts: List[str]):
        if not isinstance(node, dict):
            return
        text = node.get("Text") or node.get("Name") or None
        typ = node.get("Type") or None
        children = (node.get("Children", []) or []) + (node.get("Sensors", []) or [])
        new_path = path_parts + ([text] if text else [])
        if typ and "Value" in node and typ in wanted:
            raw_val = node.get("Value")
            val, unit = _convert_value_by_type(typ, raw_val)
            if val is not None:
                sid = node.get("SensorId") or "/" + "/".join(x for x in new_path if x)
                obj_id = make_obj_id("lhm", sid.replace("/", "_"))
                name = "LHM " + " / ".join([p for p in new_path if p][-3:])
                out.append({"type": typ, "name": name, "path": new_path, "sensor_id": sid, "value": val, "unit": unit, "obj_id": obj_id})
        for ch in children:
            walk(ch, new_path)

    walk(data, [])
    logger.debug(f"LHM collected {len(out)} sensors")
    return out


# ----- Active NIC selection (LHM first, psutil/WMI fallback) -----
import re
import urllib.parse as _upa

def _convert_throughput_to_bps(raw) -> Optional[float]:
    """Normalize LHM 'Upload/Download Speed' Value to bytes/sec."""
    v, unit = _convert_value_by_type("Throughput", raw)
    return float(v) if v is not None else None

def lhm_pick_active_nic(logger, lhm_json) -> Optional[dict]:
    """
    Return dict {name,guid,up_bps,down_bps} for NIC with highest traffic.
    Uses proper unit conversion; no arbitrary minimum threshold.
    """
    best = None

    def walk(node):
        nonlocal best
        if not isinstance(node, dict):
            return

        # NIC nodes carry the NIC icon
        if str(node.get("ImageURL", "")).endswith("nic.png"):
            name = node.get("Text") or "NIC"
            guid = None
            up_bps = 0.0
            down_bps = 0.0

            for sec in (node.get("Children") or []):
                # Probe GUID from any child SensorId like /nic/%7BGUID%7D/...
                for s in (sec.get("Children") or []):
                    sid = s.get("SensorId", "")
                    if "/nic/%7B" in sid and not guid:
                        try:
                            enc = sid.split("/nic/")[1].split("/")[0]
                            guid = _upa.unquote(enc)  # "{GUID}"
                        except Exception:
                            pass

                if sec.get("Text") == "Throughput":
                    for s in (sec.get("Children") or []):
                        label = s.get("Text", "")
                        val = _convert_throughput_to_bps(s.get("Value"))
                        if val is None:
                            continue
                        if "Upload" in label:
                            up_bps = val
                        elif "Download" in label:
                            down_bps = val

            total = up_bps + down_bps
            logger.debug(f"LHM NIC candidate: name={name} guid={guid} up={up_bps:.1f}B/s down={down_bps:.1f}B/s total={total:.1f}")
            if best is None or total > (best["up_bps"] + best["down_bps"]):
                best = {"name": name, "guid": guid, "up_bps": up_bps, "down_bps": down_bps}

        # Recurse
        for ch in (node.get("Children") or []):
            walk(ch)

    try:
        walk(lhm_json)
    except Exception as e:
        logger.debug(f"active NIC scan failed: {e}")

    # Never force a minimum: return the best we found (even if tiny traffic)
    return best

def pick_active_nic_fallback_psutil(logger) -> Optional[dict]:
    """
    If LHM can't tell us, choose an 'up' interface with the highest link speed,
    prefer non-loopback, then resolve IPv4 via WMI if possible.
    """
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        best_name = None
        best_speed = -1

        for name, st in stats.items():
            if not st.isup:
                continue
            if name.lower().startswith(("lo", "loopback")):
                continue
            # prefer a higher link speed if available; fall back to any 'up'
            speed = getattr(st, "speed", 0) or 0
            if speed > best_speed:
                best_speed = speed
                best_name = name

        if not best_name:
            return None

        ipv4 = None
        # Try psutil addresses first
        for addr in addrs.get(best_name, []):
            if getattr(addr, "family", None) == getattr(socket, "AF_INET", None):
                ipv4 = addr.address
                break

        # Derive a GUID (Windows adapters often include '{...}' in their GUID SettingID via WMI)
        guid = None
        if HAVE_WMI:
            try:
                c = wmi.WMI()
                for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    if nic.Description and best_name in nic.Description:
                        guid = getattr(nic, "SettingID", None)
                        if not ipv4 and nic.IPAddress:
                            for ip in nic.IPAddress:
                                if ip and "." in ip:
                                    ipv4 = ip
                                    break
                        break
            except Exception as e:
                logger.debug(f"WMI fallback NIC GUID lookup failed: {e}")

        logger.debug(f"psutil NIC fallback: name={best_name} speed={best_speed} IPv4={ipv4} GUID={guid}")
        return {"name": best_name, "guid": guid, "up_bps": 0.0, "down_bps": 0.0, "ipv4": ipv4}
    except Exception as e:
        logger.debug(f"psutil NIC fallback failed: {e}")
        return None


def windows_ipv4_for_guid(logger, guid: str) -> Optional[str]:
    """Return IPv4 for adapter GUID like '{...}' using WMI if available."""
    if not guid or not HAVE_WMI:
        return None
    try:
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if getattr(nic, "SettingID", None) == guid and nic.IPAddress:
                for ip in nic.IPAddress:
                    if ip and "." in ip:
                        return ip
    except Exception as e:
        logger.debug(f"WMI IP lookup failed: {e}")
    return None


def acpi_zone_temp_c(logger) -> Optional[float]:
    try:
        if HAVE_WMI:
            c = wmi.WMI(namespace="root\\WMI")
            for t in c.MSAcpi_ThermalZoneTemperature():
                v = getattr(t, "CurrentTemperature", None)
                if v:
                    celsius = (v / 10.0) - 273.15
                    logger.debug(f"ACPI ThermalZone temp={celsius:.1f}°C")
                    return round(celsius, 1)
    except Exception as e:
        logger.debug(f"ACPI temp read failed: {e}")
    return None


# ------------- SMART -------------
def detect_physical_drives(logger) -> List[str]:
    if SMART_DEVICES:
        logger.debug(f"SMART_DEVICES specified: {SMART_DEVICES}")
        return SMART_DEVICES
    devs = smartctl_scan(logger)
    if devs:
        logger.info(f"SMART devices detected via smartctl: {', '.join(devs)}")
        return devs
    devs = []
    try:
        if HAVE_WMI:
            c = wmi.WMI()
            for d in c.Win32_DiskDrive():
                devs.append(d.DeviceID)
        else:
            for i in range(0, 8):
                devs.append(f"\\\\.\\PhysicalDrive{i}")
    except Exception as e:
        logger.debug(f"WMI disk detection failed, fallback list used: {e}")
    logger.info(f"SMART devices detected: {', '.join(devs) if devs else '(none)'}")
    return devs


def smartctl_path(logger) -> Optional[str]:
    p = 'C:\\Program Files\\smartmontools\\bin\\smartctl.EXE' #shutil.which("smartctl") or shutil.which("smartctl.exe")
    logger.debug(f"smartctl path: {p}")
    return p


def smartctl_scan(logger) -> List[str]:
    exe = smartctl_path(logger)
    devs: List[str] = []
    if not exe:
        return devs
    try:
        cp = subprocess.run([exe, "--scan-open", "-j"], capture_output=True, text=True, timeout=SMART_TIMEOUT)
        if cp.returncode != 0:
            logger.debug(f"smartctl --scan-open rc={cp.returncode} err={cp.stderr.strip()}")
        if cp.stdout.strip():
            js = json.loads(cp.stdout)
            for e in js.get("devices", []) or []:
                nm = e.get("name") or e.get("info_name")
                if nm:
                    devs.append(nm)
    except Exception as e:
        logger.debug(f"smartctl scan failed: {e}")
    return devs


def run_smartctl_json(logger, dev: str) -> Optional[Dict[str, Any]]:
    exe = smartctl_path(logger)
    if not exe:
        logger.debug("smartctl not found in PATH")
        return None
    try:
        cp = subprocess.run([exe, "-a", "-j", dev], capture_output=True, text=True, timeout=SMART_TIMEOUT)
        logger.debug(f"smartctl rc={cp.returncode} dev={dev} stderr={cp.stderr.strip()}")
        if not cp.stdout.strip():
            return None
        return json.loads(cp.stdout)
    except Exception as e:
        logger.warning(f"smartctl failed for {dev}: {e}")
        return None


def smart_parse(dev: str, data: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"device": dev}
    passed = None
    if "smart_status" in data and isinstance(data["smart_status"], dict):
        passed = bool(data["smart_status"].get("passed", None))
    elif "nvme_smart_health_information_log" in data:
        cw = data["nvme_smart_health_information_log"].get("critical_warning")
        if cw is not None:
            passed = (cw == 0)
    if passed is not None:
        out["overall_health_passed"] = 1 if passed else 0

    temp = None
    nv = data.get("nvme_smart_health_information_log", {})
    if "temperature" in nv:
        temp = nv["temperature"]
    if temp is None:
        tblock = data.get("temperature", {})
        if "current" in tblock:
            temp = tblock["current"]
    if temp is not None:
        out["temperature"] = temp

    poh = None
    if "power_on_time" in data and "hours" in data["power_on_time"]:
        poh = data["power_on_time"]["hours"]
    elif "ata_smart_attributes" in data:
        for a in data["ata_smart_attributes"].get("table", []):
            if a.get("id") == 9 and "raw" in a and "value" in a["raw"]:
                try:
                    poh = int(a["raw"]["value"])
                except Exception:
                    pass
    if poh is not None:
        out["power_on_hours"] = poh

    if "percent_used" in nv:
        out["percentage_used"] = nv["percent_used"]

    dur = nv.get("data_units_read", None)
    duw = nv.get("data_units_written", None)
    if isinstance(dur, int):
        out["total_bytes_read"] = dur * 1000 * 512
    if isinstance(duw, int):
        out["total_bytes_written"] = duw * 1000 * 512
    if "ata_smart_attributes" in data:
        for a in data["ata_smart_attributes"].get("table", []):
            nm = a.get("name", "").lower()
            if nm in ("total_lbas_written", "total_lbas_read"):
                raw = a.get("raw", {}).get("value")
                try:
                    lb = int(raw)
                    key = "total_bytes_written" if "written" in nm else "total_bytes_read"
                    out[key] = lb * 512
                except Exception:
                    pass
    return out

import psutil, time, subprocess, json

def uptime_seconds() -> int:
    try:
        return int(time.time() - psutil.boot_time())
    except Exception:
        return 0

def windows_updates_pending(logger) -> int:
    """
    Count pending software updates via COM using a tiny PowerShell one-liner.
    Works without PSWindowsUpdate module.
    """
    cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()." +
        "Search(\"IsInstalled=0 and Type='Software'\").Updates.Count"
    ]
    try:
        out = subprocess.check_output(cmd, timeout=15)
        return int(out.decode(errors="ignore").strip() or "0")
    except Exception as e:
        logger.debug(f"windows_updates_pending failed: {e}")
        return 0

def services_status(logger, names_csv: str) -> tuple[list[str], list[str]]:
    """
    names_csv: comma-separated service *names* (not display names).
    """
    ok, bad = [], []
    try:
        import psutil
        for raw in [n.strip() for n in (names_csv or "").split(",") if n.strip()]:
            try:
                svc = psutil.win_service_get(raw)
                if (svc.as_dict().get("status") or "").lower() == "running":
                    ok.append(raw)
                else:
                    bad.append(raw)
            except Exception as e:
                logger.debug(f"Service {raw} check failed: {e}")
                bad.append(raw)
    except Exception as e:
        logger.debug(f"services_status failed: {e}")
    return ok, bad

def nvidia_gpu_percent(logger) -> int | None:
    # Fallback if LHM doesn’t expose GPU load
    try:
        out = subprocess.check_output(
            ["nvidia-smi",
             "--query-gpu=utilization.gpu",
             "--format=csv,noheader,nounits"],
            timeout=3
        ).decode().strip().splitlines()
        vals = [int(v) for v in out if v.strip().isdigit()]
        return int(sum(vals)/len(vals)) if vals else None
    except Exception as e:
        logger.debug(f"nvidia_gpu_percent failed: {e}")
        return None

# ------------- App -------------
@dataclass
class DiskSample:
    ts: float
    read_bytes: int
    write_bytes: int


class EWMA:
    def __init__(self, alpha: float):
        self.alpha = alpha
        self.val: Optional[float] = None

    def update(self, x: float) -> float:
        if self.val is None:
            self.val = x
        else:
            self.val = self.alpha * x + (1 - self.alpha) * self.val
        return self.val


class App:
    def __init__(self, logger, once: bool = False):
        self.logger = logger
        self.once = once

        self.client = mqtt_client(logger)

        def _on_connect(client, userdata, flags, rc, properties):
            if rc == 0:
                self.logger.info("MQTT connected rc=0")
                self.pub(avail_topic(), "online", retain=True, qos=1)
                self.publish_discovery()
            else:
                self.logger.warning(f"MQTT connect failed rc={rc}")

        def _on_disconnect(client, userdata, flags, rc, properties):
            self.logger.warning(f"MQTT disconnected rc={rc}")

        self.client.on_connect = _on_connect
        self.client.on_disconnect = _on_disconnect

        self.client.reconnect_delay_set(min_delay=1, max_delay=60)
        self.client.max_inflight_messages_set(20)
        self.client.max_queued_messages_set(0)
        
        self.last_disk: Dict[str, DiskSample] = {}

        self.load1 = EWMA(alpha=min(1.0, PUBLISH_INTERVAL / 60.0))
        self.load5 = EWMA(alpha=min(1.0, PUBLISH_INTERVAL / 300.0))
        self.load15 = EWMA(alpha=min(1.0, PUBLISH_INTERVAL / 900.0))

        self.logger.debug(f"HOSTNAME={HOSTNAME}")
        self.logger.debug(f"MQTT_HOST={MQTT_HOST} MQTT_PORT={MQTT_PORT} TLS={MQTT_TLS} CLIENT_ID={MQTT_CLIENT_ID}")
        self.logger.debug(f"BASE_TOPIC={BASE_TOPIC} DISCOVERY_PREFIX={DISCOVERY_PREFIX}")
        self.logger.debug(f"DEVICE_ID={DEVICE_ID} DEVICE_NAME={DEVICE_NAME}")
        self.logger.debug(f"PUBLISH_INTERVAL={PUBLISH_INTERVAL}")
        self.logger.debug(f"FS_TYPES_INCLUDE={FS_TYPES_INCLUDE} MOUNT_EXCLUDES={MOUNT_EXCLUDES}")
        self.logger.debug(f"SMART_ENABLE={SMART_ENABLE} SMART_TIMEOUT={SMART_TIMEOUT} SMART_DEVICES={SMART_DEVICES}")
        self.logger.debug(f"LHM_URLS_ENV={LHM_URLS_ENV} LHM_HOST={LHM_HOST} LHM_PORT={LHM_PORT} LHM_PATH={LHM_PATH} LHM_TIMEOUT={LHM_TIMEOUT}")
        self.logger.debug(f"HAVE_WMI={HAVE_WMI}")

    def try_reconnect(self):
        try:
            self.logger.info("Attempting MQTT reconnect...")
            self.client.reconnect()
            return True
        except Exception as e:
            self.logger.debug(f"Immediate reconnect failed: {e}")
            return False

    def pub(self, topic: str, payload: str, retain: bool = False, qos: int = 0):
        self.logger.debug(f"MQTT PUBLISH [{qos}]{'[retain]' if retain else ''} {topic} -> {payload}")
        res = self.client.publish(topic, payload, qos=qos, retain=retain)
        try:
            rc = res.rc
        except Exception:
            rc = getattr(res, "rc", none)

        if rc is None:
            return res

        if rc != mqtt.MQTT_ERR_SUCCESS:
            self.logger.warning(f"Publish rc={rc} (not connected?).")
            if rc == mqtt.MQTT_ERR_NO_CONN:
                if self.try_reconnect():
                    self.client.publish(avail_topic(), "online", qos=1, retain=True)
                    res = self.client.publish(topic, payload, qos=qos, retain=retain)
                    self.logger.debug(f"Retry publish rc={res.rc}")
        return res

    def publish_discovery(self):
        c = self.client
        self.pub(avail_topic(), "online", retain=True, qos=1)

        pub_bin_sensor(c, make_obj_id("status", "overall_ok"), "Overall Status OK", f"{BASE_TOPIC}/status/overall_ok")
        pub_config(c, "sensor", make_obj_id("status", "summary"), "Overall Status Summary",
                   f"{BASE_TOPIC}/status/summary", icon="mdi:card-text-outline")

        for name in ("percent", "load_1m", "load_5m", "load_15m"):
            st = f"{BASE_TOPIC}/cpu/{name}"
            nm = {"percent": "CPU Utilization", "load_1m": "CPU Load 1m",
                  "load_5m": "CPU Load 5m", "load_15m": "CPU Load 15m"}[name]
            unit = "%" if name == "percent" else ""
            pub_config(c, "sensor", make_obj_id("cpu", name), nm, st,
                       unit=unit, icon="mdi:chip", state_class="measurement")

        pub_config(c, "sensor", make_obj_id("cpu", "cores"), "CPU Cores",
                   f"{BASE_TOPIC}/cpu/cores", icon="mdi:chip", state_class="measurement")

        pub_config(c, "sensor", make_obj_id("cpu", "temp_package"), "CPU Temp (pkg)",
                   f"{BASE_TOPIC}/cpu/temp/package", unit="°C",
                   device_class="temperature", state_class="measurement")
        pub_config(c, "sensor", make_obj_id("cpu", "temp_max"), "CPU Temp (max)",
                   f"{BASE_TOPIC}/cpu/temp/max", unit="°C",
                   device_class="temperature", state_class="measurement")

        try:
            sensors = lhm_collect(self.logger)
            for s in sensors:
                self.pub(f"{BASE_TOPIC}/lhm/{s['obj_id']}", f"{s['value']}")
            lhm_data = _get_lhm_json(self.logger)
            nic = lhm_pick_active_nic(self.logger, lhm_data)
            if not nic:
                nic = pick_active_nic_fallback_psutil(self.logger)
            print(f"{nic=}")
            if nic:
                self.pub(f"{BASE_TOPIC}/network/active/name", nic['name'])
                self.pub(f"{BASE_TOPIC}/network/active/up_bps", f"{nic['up_bps']}")
                self.pub(f"{BASE_TOPIC}/network/active/down_bps", f"{nic['down_bps']}")
                ip = windows_ipv4_for_guid(self.logger, nic.get('guid'))
                if ip:
                    self.pub(f"{BASE_TOPIC}/network/active/ipv4", ip)
        except Exception as e:
            self.logger.debug(f"LHM publish failed: {e}")

        for key, label, unit in [
            ("total", "Memory Total", "GiB"),
            ("used", "Memory Used", "GiB"),
            ("available", "Memory Available", "GiB"),
            ("percent", "Memory Percent", "%"),
        ]:
            pub_config(c, "sensor", make_obj_id("mem", key), label,
                       f"{BASE_TOPIC}/mem/{key}", unit=unit, icon="mdi:memory", state_class="measurement")

        parts = psutil.disk_partitions(all=False)
        self.logger.debug(f"disk_partitions: {parts}")
        for p in parts:
            if FS_TYPES_INCLUDE and p.fstype not in FS_TYPES_INCLUDE:
                self.logger.debug(f"Skip FS (fstype filtered): {p.mountpoint} fstype={p.fstype}")
                continue
            mnt = (p.mountpoint or "").rstrip("\\")
            if any(mnt.upper().startswith(ex.upper()) for ex in MOUNT_EXCLUDES):
                self.logger.debug(f"Skip FS (excluded): {mnt}")
                continue
            obj_tag = make_obj_id("fs", mnt or p.device)
            for suff, unit in (("total", "GiB"), ("used", "GiB"), ("free", "GiB"), ("percent", "%")):
                pub_config(c, "sensor", make_obj_id(obj_tag, suff), f"FS {mnt or p.device} {suff}",
                           f"{BASE_TOPIC}/fs/{obj_tag}/{suff}", unit=unit, icon="mdi:harddisk", state_class="measurement")

        for disk_name in sorted(psutil.disk_io_counters(perdisk=True).keys()):
            for suff, unit in (("read_bytes", "B"), ("write_bytes", "B"), ("read_rate", "B/s"), ("write_rate", "B/s")):
                pub_config(c, "sensor", make_obj_id("disk", disk_name, suff),
                           f"Disk {disk_name} {suff}", f"{BASE_TOPIC}/disk/{disk_name}/{suff}",
                           unit=unit, icon="mdi:swap-horizontal", state_class="measurement")

        pub_config(c, "sensor", make_obj_id("battery", "percent"), "Battery Percent",
                   f"{BASE_TOPIC}/battery/percent", "%", icon="mdi:battery", state_class="measurement")
        pub_bin_sensor(c, make_obj_id("battery", "plugged"), "Battery Plugged",
                       f"{BASE_TOPIC}/battery/plugged", icon="mdi:power-plug")

        try:
            lhm_sensors = lhm_collect(self.logger)
            for s in lhm_sensors:
                dc = None
                icon = None
                if s['type'] == 'Temperature':
                    dc, icon = 'temperature', 'mdi:thermometer'
                elif s['type'] == 'Voltage':
                    dc, icon = 'voltage', 'mdi:flash-outline'
                elif s['type'] == 'Power':
                    dc, icon = 'power', 'mdi:lightning-bolt-outline'
                elif s['type'] == 'Clock':
                    dc, icon = None, 'mdi:chip'
                elif s['type'] in ('Load','Level'):
                    dc, icon = None, 'mdi:gauge'
                elif s['type'] in ('Throughput',):
                    dc, icon = None, 'mdi:swap-vertical'
                elif s['type'] in ('Data','SmallData','Energy','Factor'):
                    dc, icon = None, 'mdi:database'
                pub_config(c, 'sensor', s['obj_id'], s['name'], f"{BASE_TOPIC}/lhm/{s['obj_id']}",
                           unit=s['unit'], device_class=dc, icon=icon, state_class='measurement')
        except Exception as e:
            self.logger.debug(f"LHM discovery failed: {e}")

        try:
            pub_config(c, 'sensor', make_obj_id('net', 'active_name'), 'Network Active Name', f"{BASE_TOPIC}/network/active/name")
            pub_config(c, 'sensor', make_obj_id('net', 'active_up_bps'), 'Network Active Up', f"{BASE_TOPIC}/network/active/up_bps", unit='B/s', icon='mdi:upload')
            pub_config(c, 'sensor', make_obj_id('net', 'active_down_bps'), 'Network Active Down', f"{BASE_TOPIC}/network/active/down_bps", unit='B/s', icon='mdi:download')
            pub_config(c, 'sensor', make_obj_id('net', 'active_ipv4'), 'Network Active IPv4', f"{BASE_TOPIC}/network/active/ipv4")
        except Exception as e:
            self.logger.debug(f"Active NIC discovery failed: {e}")

        if SMART_ENABLE and smartctl_path(self.logger):
            for dev in detect_physical_drives(self.logger):
                clean = make_obj_id("smart", os.path.basename(dev).lower())
                pub_bin_sensor(c, f"{clean}_health", f"SMART {dev} Health",
                               f"{BASE_TOPIC}/smart/{clean}/overall_health")
                for key, label, unit, icon in [
                    ("temperature", "Temperature", "°C", "mdi:thermometer"),
                    ("power_on_hours", "Power On Hours", "h", "mdi:timer-outline"),
                    ("percentage_used", "Percentage Used", "%", "mdi:gauge"),
                    ("total_bytes_written", "Total Bytes Written", "B", "mdi:database"),
                    ("total_bytes_read", "Total Bytes Read", "B", "mdi:database"),
                ]:
                    pub_config(c, "sensor", f"{clean}_{key}", f"SMART {dev} {label}",
                               f"{BASE_TOPIC}/smart/{clean}/{key}",
                               unit=unit, icon=icon, state_class="measurement")
        # Uptime
        pub_config(c, "sensor", make_obj_id("uptime_s"), "Uptime (s)",
                f"{BASE_TOPIC}/uptime_s", icon="mdi:timer-outline", state_class="measurement")

        # Updates pending
        pub_config(c, "sensor", make_obj_id("updates_pending"), "Updates Pending",
                f"{BASE_TOPIC}/updates/pending", icon="mdi:update", state_class="measurement")

        # GPU percent (generic)
        pub_config(c, "sensor", make_obj_id("gpu", "percent"), "GPU Utilization",
                f"{BASE_TOPIC}/gpu/percent", unit="%", icon="mdi:gpu", state_class="measurement")

        # Services rollup
        pub_bin_sensor(c, make_obj_id("services", "ok"), "Services OK",
                    f"{BASE_TOPIC}/services/ok")
        pub_config(c, "sensor", make_obj_id("services", "checked"), "Services Checked",
                f"{BASE_TOPIC}/services/checked", icon="mdi:playlist-check", state_class="measurement")
        pub_config(c, "sensor", make_obj_id("services", "bad_list"), "Services (Bad CSV)",
                f"{BASE_TOPIC}/services/bad_list", icon="mdi:alert")

        # Per-service binary_sensors (for Auto-entities “services glob”)
        services = env_list("WATCH_SERVICES")
        for svc in services:
            svc_clean = make_obj_id(svc)
            obj_id = make_obj_id(DEVICE_ID, svc_clean, "service")  # -> <hostname>_<service>_service
            st = f"{BASE_TOPIC}/services/{svc_clean}/running"
            # entity_category=diagnostic + payload_on/off already provided by pub_bin_sensor()
            pub_bin_sensor(c, obj_id, f"Service {svc}", st, icon="mdi:cog")


    def publish_once(self):
        cpu_pct = psutil.cpu_percent(interval=None)
        l1 = self.load1.update(cpu_pct)
        l5 = self.load5.update(cpu_pct)
        l15 = self.load15.update(cpu_pct)
        self.logger.debug(f"CPU pct={cpu_pct:.2f} ewma: 1m={l1:.2f} 5m={l5:.2f} 15m={l15:.2f}")

        self.pub(f"{BASE_TOPIC}/cpu/percent", f"{cpu_pct:.2f}")
        self.pub(f"{BASE_TOPIC}/cpu/load_1m", f"{l1:.2f}")
        self.pub(f"{BASE_TOPIC}/cpu/load_5m", f"{l5:.2f}")
        self.pub(f"{BASE_TOPIC}/cpu/load_15m", f"{l15:.2f}")

        try:
            cores_logical = psutil.cpu_count(logical=True) or 0
        except Exception as e:
            self.logger.warning(f"cpu_count failed: {e}")
            cores_logical = 0
        self.pub(f"{BASE_TOPIC}/cpu/cores", str(cores_logical))

        pkg = None
        tmax = None
        temps = lhm_read_temps(self.logger)
        if temps:
            tmax = max(temps.values())
            for k, v in temps.items():
                lk = k.lower()
                if "package" in lk or ("cpu" in lk and "core" not in lk):
                    pkg = v
                    break
        if pkg is None:
            pkg = acpi_zone_temp_c(self.logger)
        self.logger.debug(f"Temps: pkg={pkg} max={tmax}")
        if pkg is not None:
            self.pub(f"{BASE_TOPIC}/cpu/temp/package", f"{pkg:.1f}")
        if tmax is not None:
            self.pub(f"{BASE_TOPIC}/cpu/temp/max", f"{tmax:.1f}")

        try:
            sensors = lhm_collect(self.logger)
            for s in sensors:
                self.pub(f"{BASE_TOPIC}/lhm/{s['obj_id']}", f"{s['value']}")
            lhm_data = _get_lhm_json(self.logger)
            nic = lhm_pick_active_nic(self.logger, lhm_data)
            if not nic:
                nic = pick_active_nic_fallback_psutil(self.logger)
            if nic:
                self.pub(f"{BASE_TOPIC}/network/active/name", nic['name'])
                self.pub(f"{BASE_TOPIC}/network/active/up_bps", f"{nic['up_bps']}")
                self.pub(f"{BASE_TOPIC}/network/active/down_bps", f"{nic['down_bps']}")
                ip = windows_ipv4_for_guid(self.logger, nic.get('guid'))
                if ip:
                    self.pub(f"{BASE_TOPIC}/network/active/ipv4", ip)
        except Exception as e:
            self.logger.debug(f"LHM publish failed: {e}")

        vm = psutil.virtual_memory()
        self.logger.debug(f"Memory: total={vm.total} used={vm.used} avail={vm.available} pct={vm.percent}")
        self.pub(f"{BASE_TOPIC}/mem/total", f"{bytes_to_gib(vm.total):.3f}")
        self.pub(f"{BASE_TOPIC}/mem/used", f"{bytes_to_gib(vm.used):.3f}")
        self.pub(f"{BASE_TOPIC}/mem/available", f"{bytes_to_gib(vm.available):.3f}")
        self.pub(f"{BASE_TOPIC}/mem/percent", f"{vm.percent:.2f}")

        parts = psutil.disk_partitions(all=False)
        for p in parts:
            mnt = (p.mountpoint or "").rstrip("\\")
            self.logger.debug(f"FS candidate: mnt={mnt} fstype={p.fstype} device={p.device}")
            if FS_TYPES_INCLUDE and p.fstype not in FS_TYPES_INCLUDE:
                self.logger.debug(f"  -> skip (fstype filtered)")
                continue
            if any(mnt.upper().startswith(ex.upper()) for ex in MOUNT_EXCLUDES):
                self.logger.debug(f"  -> skip (excluded)")
                continue
            try:
                du = psutil.disk_usage(p.mountpoint)
            except Exception as e:
                self.logger.debug(f"  -> disk_usage failed: {e}")
                continue
            tag = make_obj_id("fs", mnt or p.device)
            self.logger.debug(f"FS publish: tag={tag} total={du.total} used={du.used} free={du.free} pct={du.percent}")
            self.pub(f"{BASE_TOPIC}/fs/{tag}/total", f"{bytes_to_gib(du.total):.3f}")
            self.pub(f"{BASE_TOPIC}/fs/{tag}/used", f"{bytes_to_gib(du.used):.3f}")
            self.pub(f"{BASE_TOPIC}/fs/{tag}/free", f"{bytes_to_gib(du.free):.3f}")
            self.pub(f"{BASE_TOPIC}/fs/{tag}/percent", f"{du.percent:.2f}")

        now = time.time()
        io = psutil.disk_io_counters(perdisk=True)
        new_last = dict(self.last_disk)
        for disk_name, st in io.items():
            self.logger.debug(f"Disk IO raw: {disk_name} rB={st.read_bytes} wB={st.write_bytes}")
            self.pub(f"{BASE_TOPIC}/disk/{disk_name}/read_bytes", str(st.read_bytes))
            self.pub(f"{BASE_TOPIC}/disk/{disk_name}/write_bytes", str(st.write_bytes))
            prev = self.last_disk.get(disk_name)
            if prev:
                dt = max(0.001, now - prev.ts)
                r_rate = max(0, st.read_bytes - prev.read_bytes) / dt
                w_rate = max(0, st.write_bytes - prev.write_bytes) / dt
                self.logger.debug(f"Disk IO rate: {disk_name} dt={dt:.3f}s r={r_rate:.1f}B/s w={w_rate:.1f}B/s")
                self.pub(f"{BASE_TOPIC}/disk/{disk_name}/read_rate", f"{r_rate:.2f}")
                self.pub(f"{BASE_TOPIC}/disk/{disk_name}/write_rate", f"{w_rate:.2f}")
            new_last[disk_name] = DiskSample(now, st.read_bytes, st.write_bytes)
        self.last_disk = new_last

        try:
            bat = psutil.sensors_battery()
        except Exception as e:
            self.logger.debug(f"sensors_battery failed: {e}")
            bat = None
        if bat is not None:
            self.logger.debug(f"Battery: pct={bat.percent} plugged={bat.power_plugged}")
            self.pub(f"{BASE_TOPIC}/battery/percent", f"{bat.percent:.1f}")
            self.pub(f"{BASE_TOPIC}/battery/plugged", "1" if bat.power_plugged else "0")

        try:
            lhm_sensors = lhm_collect(self.logger)
            for s in lhm_sensors:
                dc = None
                icon = None
                if s['type'] == 'Temperature':
                    dc, icon = 'temperature', 'mdi:thermometer'
                elif s['type'] == 'Voltage':
                    dc, icon = 'voltage', 'mdi:flash-outline'
                elif s['type'] == 'Power':
                    dc, icon = 'power', 'mdi:lightning-bolt-outline'
                elif s['type'] == 'Clock':
                    dc, icon = None, 'mdi:chip'
                elif s['type'] in ('Load','Level'):
                    dc, icon = None, 'mdi:gauge'
                elif s['type'] in ('Throughput',):
                    dc, icon = None, 'mdi:swap-vertical'
                elif s['type'] in ('Data','SmallData','Energy','Factor'):
                    dc, icon = None, 'mdi:database'
                pub_config(self.client, 'sensor', s['obj_id'], s['name'], f"{BASE_TOPIC}/lhm/{s['obj_id']}",
                           unit=s['unit'], device_class=dc, icon=icon, state_class='measurement')
        except Exception as e:
            self.logger.debug(f"LHM discovery failed: {e}")

        try:
            pub_config(self.client, 'sensor', make_obj_id('net', 'active_name'), 'Network Active Name', f"{BASE_TOPIC}/network/active/name")
            pub_config(self.client, 'sensor', make_obj_id('net', 'active_up_bps'), 'Network Active Up', f"{BASE_TOPIC}/network/active/up_bps", unit='B/s', icon='mdi:upload')
            pub_config(self.client, 'sensor', make_obj_id('net', 'active_down_bps'), 'Network Active Down', f"{BASE_TOPIC}/network/active/down_bps", unit='B/s', icon='mdi:download')
            pub_config(self.client, 'sensor', make_obj_id('net', 'active_ipv4'), 'Network Active IPv4', f"{BASE_TOPIC}/network/active/ipv4")
        except Exception as e:
            self.logger.debug(f"Active NIC discovery failed: {e}")

        if SMART_ENABLE and smartctl_path(self.logger):
            for dev in detect_physical_drives(self.logger):
                data = run_smartctl_json(self.logger, dev)
                if not data:
                    continue
                parsed = smart_parse(dev, data)
                clean = make_obj_id("smart", os.path.basename(dev).lower())
                self.logger.debug(f"SMART parsed {dev}: {parsed}")
                if "overall_health_passed" in parsed:
                    self.pub(f"{BASE_TOPIC}/smart/{clean}/overall_health",
                             "1" if parsed["overall_health_passed"] else "0")
                for key in ("temperature", "power_on_hours", "percentage_used",
                            "total_bytes_written", "total_bytes_read"):
                    if key in parsed:
                        self.pub(f"{BASE_TOPIC}/smart/{clean}/{key}", str(parsed[key]))

        issues: List[str] = []
        notes: List[str] = []

        try:
            if vm.percent >= 90:
                issues.append(f"RAM {vm.percent:.0f}%")
            else:
                notes.append(f"RAM {vm.percent:.0f}%")
        except Exception:
            pass

        if tmax is not None:
            if tmax >= 90:
                issues.append(f"CPU {tmax:.0f}°C")
            elif tmax >= 80:
                notes.append(f"CPU {tmax:.0f}°C")
            else:
                notes.append(f"CPU {tmax:.0f}°C")

        try:
            for p in parts:
                mnt = (p.mountpoint or "").rstrip("\\")
                if FS_TYPES_INCLUDE and p.fstype not in FS_TYPES_INCLUDE:
                    continue
                if any(mnt.upper().startswith(ex.upper()) for ex in MOUNT_EXCLUDES):
                    continue
                du = psutil.disk_usage(p.mountpoint)
                if du.percent >= 95:
                    issues.append(f"FS {mnt or p.device} {du.percent:.0f}%")
        except Exception:
            pass

        # Uptime
        self.pub(f"{BASE_TOPIC}/uptime_s", str(uptime_seconds()))

        # Updates
        upd = windows_updates_pending(self.logger)
        self.pub(f"{BASE_TOPIC}/updates/pending", str(upd))
        if upd > 0:
            issues.append(f"Updates {upd}")

        # GPU percent
        gpu_pct = None
        try:
            # Try to infer from LHM “Load / GPU” if present; else fall back to nvidia-smi
            # You’re already mirroring LHM sensors into BASE_TOPIC/lhm/* above.
            # If you kept the list of LHM sensors this tick, you could scan it; otherwise:
            gpu_pct = nvidia_gpu_percent(self.logger)
        except Exception:
            pass
        if gpu_pct is not None:
            self.pub(f"{BASE_TOPIC}/gpu/percent", str(int(gpu_pct)))
            if gpu_pct >= 95:
                issues.append(f"GPU {gpu_pct}%")
            else:
                notes.append(f"GPU {gpu_pct}%")

        # Services (optional; controlled by WATCH_SERVICES env)
        watch = os.getenv("WATCH_SERVICES", "")
        ok, bad = services_status(self.logger, watch)
        self.pub(f"{BASE_TOPIC}/services/checked", str(len(ok) + len(bad)))
        self.pub(f"{BASE_TOPIC}/services/ok", "1" if not bad else "0")
        self.pub(f"{BASE_TOPIC}/services/bad_list", ",".join(bad))
        if bad:
            issues.append("Svc " + ",".join(bad))

        # Per-service state topics (1 running / 0 not running)
        services = env_list("WATCH_SERVICES")
        ok_set = set(ok)
        for svc in services:
            svc_clean = make_obj_id(svc)
            st = f"{BASE_TOPIC}/services/{svc_clean}/running"
            self.pub(st, "1" if svc in ok_set else "0")

        # existing overall_ok/summary block already handles ‘issues’/’notes’

        overall_ok = "0" if issues else "1"
        summary = "OK"
        if issues:
            summary = "Issues: " + "; ".join(issues)
            if notes:
                summary += " | " + ", ".join(notes)
        elif notes:
            summary += ": " + ", ".join(notes)
        self.logger.info(f"Overall: ok={overall_ok} summary='{summary}'")
        self.pub(f"{BASE_TOPIC}/status/overall_ok", overall_ok)
        self.pub(f"{BASE_TOPIC}/status/summary", summary[:480])

    def run(self):
        self.client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
        self.client.loop_start()
        self.pub(avail_topic(), "online", retain=True, qos=1)
        self.logger.info(f"Starting win_hwmon on '{HOSTNAME}' publish_interval={PUBLISH_INTERVAL}s")
        self.publish_discovery()
        try:
            if self.once:
                self.publish_once()
            else:
                while True:
                    if not self.client.is_connected():
                        self.logger.debug("MQTT not connected; skipping this publish cycle.")
                        self.try_reconnect()
                    else:
                        self.publish_once()
                    time.sleep(PUBLISH_INTERVAL)
        except KeyboardInterrupt:
            self.logger.info("Exiting (KeyboardInterrupt)")
        finally:
            self.pub(avail_topic(), "offline", retain=True, qos=1)
            time.sleep(0.1)
            self.client.loop_stop()
            self.client.disconnect()


def parse_args() -> Tuple[bool, str, bool]:
    parser = argparse.ArgumentParser(description="Windows hardware → MQTT exporter")
    parser.add_argument("--debug", action="store_true",
                        help="Enable DEBUG logging (overrides --log-level)")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"),
                        help="Logging level: DEBUG, INFO, WARNING, ERROR (default: %(default)s)")
    parser.add_argument("--once", action="store_true",
                        help="Publish once and exit (for testing)")
    args = parser.parse_args()
    debug_env = env_bool("DEBUG", False)
    level = "DEBUG" if (args.debug or debug_env) else args.log_level
    return args.once, level.upper(), (args.debug or debug_env)


if __name__ == "__main__":
    once, level_name, is_debug = parse_args()
    logger = setup_logger(level_name)
    logger.info(f"win_hwmon starting (level={level_name}, once={once})")
    if is_debug:
        logger.debug(f"ENV MQTT_HOST={os.getenv('MQTT_HOST')} MQTT_PORT={os.getenv('MQTT_PORT')} USER={os.getenv('MQTT_USERNAME')}")
        logger.debug(f"ENV BASE_TOPIC={os.getenv('BASE_TOPIC')} DEVICE_ID={os.getenv('DEVICE_ID')} DISCOVERY_PREFIX={os.getenv('DISCOVERY_PREFIX')}")
        logger.debug(f"ENV FS_TYPES_INCLUDE={os.getenv('FS_TYPES_INCLUDE')} MOUNT_EXCLUDES={os.getenv('MOUNT_EXCLUDES')}")
        logger.debug(f"ENV SMART_ENABLE={os.getenv('SMART_ENABLE')} SMART_DEVICES={os.getenv('SMART_DEVICES')}")
        logger.debug(f"ENV LHM_URLS={os.getenv('LHM_URLS')} LHM_URL={os.getenv('LHM_URL')} LHM_HOST={os.getenv('LHM_HOST')} LHM_PORT={os.getenv('LHM_PORT')}")
    App(logger=logger, once=once).run()
