"""NetScope - single-file Streamlit WiFi/LAN device scanner.

Run:      streamlit run app.py
Password: set env NETSCOPE_PASSWORD (or .streamlit/secrets.toml) to require login.
Note:     the scan runs on the machine where this app runs, so it sees THAT machine's network.
"""
from __future__ import annotations

import csv
import hmac
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import pandas as pd
import psutil
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
OUI_FILE = APP_DIR / "oui.csv"
WIN_NMAP = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]
MAX_HOSTS = 65536  # refuse ranges bigger than /16

# ----------------------------------------------------------------------------- helpers


def normalize_mac(raw: str | None) -> str | None:
    s = re.sub(r"[^0-9A-Fa-f]", "", raw or "")
    return ":".join(s[i:i + 2] for i in range(0, 12, 2)).upper() if len(s) == 12 else None


def is_randomized(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0b10)


def parse_oui_text(text: str) -> dict[str, str]:
    """Parse IEEE oui.csv or Nmap's nmap-mac-prefixes into {PREFIX6: vendor}."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^[0-9A-Fa-f]{6}\s", line):  # nmap format: "B827EB Raspberry Pi"
            p, n = line.split(None, 1)
            table[p.upper()] = n.strip()
        elif "," in line:  # IEEE csv: Registry,Assignment,Organization Name,Address
            row = next(csv.reader([line]))
            if len(row) >= 3 and len(row[1]) == 6:
                table[row[1].upper()] = row[2].strip()
    return table


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse `nmap -sn -oX -` output. Returns [] on malformed input."""
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, TypeError):
        return []
    out = []
    for host in root.findall("host"):
        st_ = host.find("status")
        if st_ is None or st_.get("state") != "up":
            continue
        ip = mac = nvendor = None
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, nvendor = normalize_mac(a.get("addr")), a.get("vendor")
        if ip:
            hn = host.find("hostnames/hostname")
            out.append({"ip": ip, "mac": mac, "nmap_vendor": nvendor,
                        "hostname": hn.get("name") if hn is not None else None})
    return out


def vendor_for(table: dict[str, str], mac: str | None, nmap_vendor: str | None) -> tuple[str, str]:
    """Return (vendor, confidence). Never invents a vendor."""
    if not mac:
        return "Unavailable", "-"
    if is_randomized(mac):
        return "Unknown (randomized MAC)", "Randomized"
    v = table.get(mac.replace(":", "")[:6])
    if v:
        return v, "Registry"
    if nmap_vendor:
        return nmap_vendor, "Nmap"
    return "Unknown", "None"


def find_nmap(custom: str = "") -> str | None:
    for c in (custom, os.environ.get("NETSCOPE_NMAP", ""), str(APP_DIR / "nmap" / "nmap.exe"),
              shutil.which("nmap") or "", *WIN_NMAP):
        if c and Path(c).is_file():
            return c
    return None


def default_gateway() -> str | None:
    try:
        if sys.platform == "win32":
            out = subprocess.run(["route", "print", "-4"], capture_output=True, text=True, timeout=5).stdout
            best = None
            for line in out.splitlines():
                m = re.match(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\d+)", line)
                if m and (best is None or int(m.group(2)) < best[0]):
                    best = (int(m.group(2)), m.group(1))
            return best[1] if best else None
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) >= 3 and f[1] == "00000000":
                return ".".join(str(b) for b in bytes.fromhex(f[2])[::-1])
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return None


def detect_networks() -> list[dict]:
    gw = default_gateway()
    stats = psutil.net_if_stats()
    nets = []
    for name, addrs in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        mac = next((normalize_mac(a.address) for a in addrs if a.family == psutil.AF_LINK), None)
        for a in addrs:
            if a.family.name != "AF_INET" or not a.netmask:
                continue
            ip = ipaddress.IPv4Address(a.address)
            if ip.is_loopback or ip.is_link_local:
                continue
            net = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
            nets.append({"name": name, "ip": a.address, "mask": a.netmask, "cidr": str(net), "mac": mac,
                         "gateway": gw if gw and ipaddress.IPv4Address(gw) in net else None})
    nets.sort(key=lambda n: n["gateway"] is None)
    return nets


def validate_cidr(text: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.IPv4Network(text.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid network range: {text!r}") from exc
    if net.num_addresses > MAX_HOSTS:
        raise ValueError("Range too large (maximum is a /16).")
    return net


def run_scan(nmap_exe: str, cidr: str, timeout: int) -> tuple[list[dict], str | None]:
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        p = subprocess.run([nmap_exe, "-sn", "-oX", "-", cidr], capture_output=True, text=True,
                           timeout=timeout, creationflags=flags)
    except subprocess.TimeoutExpired:
        return [], f"Scan timed out after {timeout}s. Try a smaller range or a longer timeout."
    except OSError as exc:
        return [], f"Could not start Nmap: {exc}"
    if p.returncode != 0:
        err = p.stderr.strip() or "Nmap failed."
        if "npcap" in err.lower():
            err += "\n\nInstall Npcap (included in the Nmap installer) and restart."
        return [], err
    return parse_nmap_xml(p.stdout), None


@st.cache_resource(show_spinner=False)
def load_vendor_db(nmap_exe: str, oui_mtime: float) -> tuple[dict[str, str], str]:
    table: dict[str, str] = {}
    sources = []
    if nmap_exe:
        p = Path(nmap_exe).with_name("nmap-mac-prefixes")
        if p.exists():
            table.update(parse_oui_text(p.read_text(encoding="utf-8", errors="replace")))
            sources.append("Nmap")
    if OUI_FILE.exists():
        table.update(parse_oui_text(OUI_FILE.read_text(encoding="utf-8", errors="replace")))
        sources.append("IEEE oui.csv")
    return table, " + ".join(sources) or "none"


def require_password() -> None:
    pw = os.environ.get("NETSCOPE_PASSWORD", "")
    if not pw:
        try:
            pw = str(st.secrets.get("NETSCOPE_PASSWORD", ""))
        except Exception:  # no secrets file
            pw = ""
    if not pw or st.session_state.get("auth"):
        return
    st.title("📡 NetScope")
    with st.form("login"):
        entry = st.text_input("Password", type="password")
        if st.form_submit_button("Login", type="primary"):
            if hmac.compare_digest(entry, pw):
                st.session_state.auth = True
                st.rerun()
            st.error("Wrong password.")
    st.stop()

# ----------------------------------------------------------------------------- UI

st.set_page_config(page_title="NetScope", page_icon="📡", layout="wide")
require_password()
st.session_state.setdefault("result", None)
st.session_state.setdefault("history", [])

with st.sidebar:
    st.header("📡 NetScope")
    nets = detect_networks()
    labels = [f"{n['name']} - {n['ip']} ({n['cidr']})" for n in nets] + ["Custom range..."]
    choice = st.selectbox("Network", labels, help="Detected from this machine's real interfaces.")
    idx = labels.index(choice)
    selected = nets[idx] if idx < len(nets) else None
    if selected:
        st.caption(f"IP {selected['ip']} · mask {selected['mask']} · gateway {selected['gateway'] or 'n/a'}")
        cidr_text = selected["cidr"]
    else:
        cidr_text = st.text_input("Range (CIDR)", "192.168.1.0/24")
    timeout = st.slider("Scan timeout (seconds)", 30, 600, 120, step=30)
    with st.expander("Advanced"):
        custom_nmap = st.text_input("Nmap path (optional)", placeholder=r"C:\Program Files (x86)\Nmap\nmap.exe")
        up = st.file_uploader("Vendor list (IEEE oui.csv)", type=["csv", "txt"],
                              help="Optional. Nmap's own vendor list is used automatically.")
        if up is not None and st.button("Save vendor list"):
            OUI_FILE.write_bytes(up.getvalue())
            st.success("Saved. Reload the page.")
    nmap_exe = find_nmap(custom_nmap)
    vendor_db, db_source = load_vendor_db(nmap_exe or "", OUI_FILE.stat().st_mtime if OUI_FILE.exists() else 0.0)
    st.divider()
    st.write("Nmap: " + ("✅ found" if nmap_exe else "❌ not found"))
    st.write(f"Vendor DB: {len(vendor_db):,} entries ({db_source})")

st.title("📡 NetScope")
st.caption("Discover devices on your local WiFi/LAN. Only scan networks you own or are authorized to scan.")
if Path("/mount/src").exists():  # Streamlit Community Cloud
    st.info("☁️ This app is running on a cloud server, so a scan shows the **server's** network, not your home WiFi. "
            "Run it on a PC inside your own network to scan your devices.")

if not nmap_exe:
    st.error("**Nmap is not installed (or not found).** Install it from https://nmap.org/download.html "
             "(keep the Npcap option ticked), restart this app, or set the path under Sidebar → Advanced.")

try:
    net = validate_cidr(cidr_text)
    range_error = None
except ValueError as exc:
    net, range_error = None, str(exc)
    st.error(range_error)

confirmed = True
if net is not None and not net.is_private:
    st.warning("This range is **not** a private network. Scan only if you are authorized.")
    confirmed = st.checkbox("I am authorized to scan this range")

if st.button("🔍 Scan Network", type="primary", disabled=not (nmap_exe and net and confirmed)):
    started = datetime.now()
    with st.spinner(f"Scanning {net} ... this can take up to a minute."):
        raw, err = run_scan(nmap_exe, str(net), timeout)
    if err:
        st.session_state.result = {"time": started, "range": str(net), "status": "failed", "error": err, "rows": []}
    else:
        rows = []
        for d in raw:
            mac, host = d["mac"], d["hostname"]
            if selected and d["ip"] == selected["ip"]:
                mac, host = mac or selected["mac"], host or "This device"
            vendor, conf = vendor_for(vendor_db, mac, d["nmap_vendor"])
            rows.append({"Device Name": host or "Unknown", "Manufacturer": vendor, "IP Address": d["ip"],
                         "MAC Address": mac or "Unavailable", "Confidence": conf,
                         "Method": "Nmap ARP" if mac else "Nmap ping", "Last Seen": started.strftime("%Y-%m-%d %H:%M:%S")})
        rows.sort(key=lambda r: ipaddress.IPv4Address(r["IP Address"]))
        st.session_state.result = {"time": started, "range": str(net), "status": "completed", "error": None, "rows": rows}
    r = st.session_state.result
    st.session_state.history.insert(0, {"Time": r["time"].strftime("%Y-%m-%d %H:%M:%S"), "Range": r["range"],
                                        "Status": r["status"], "Devices": len(r["rows"])})

tab_dev, tab_hist, tab_help = st.tabs(["Devices", "Scan History", "Help & Limits"])

with tab_dev:
    res = st.session_state.result
    if res is None:
        st.info("No scan yet. Pick your network in the sidebar and press **Scan Network**.")
    elif res["status"] == "failed":
        st.error(f"Scan failed: {res['error']}")
    else:
        df = pd.DataFrame(res["rows"])
        identified = int((df["Confidence"].isin(["Registry", "Nmap"])).sum()) if not df.empty else 0
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Devices found", len(df))
        c2.metric("Vendors identified", identified)
        c3.metric("Unknown vendors", len(df) - identified)
        c4.metric("Last scan", res["time"].strftime("%H:%M:%S"), res["status"])
        if df.empty:
            st.warning("Scan finished but no devices responded. Some devices ignore discovery probes.")
        else:
            f1, f2, f3 = st.columns([3, 3, 2])
            q = f1.text_input("Search", placeholder="IP, MAC, name or manufacturer")
            vend = f2.multiselect("Manufacturer", sorted(df["Manufacturer"].unique()))
            only_unknown = f3.checkbox("Only unknown", help="Hide devices with an identified vendor")
            view = df
            if q:
                mask = view.apply(lambda col: col.astype(str).str.contains(q, case=False, regex=False)).any(axis=1)
                view = view[mask]
            if vend:
                view = view[view["Manufacturer"].isin(vend)]
            if only_unknown:
                view = view[~view["Confidence"].isin(["Registry", "Nmap"])]
            st.dataframe(view, hide_index=True, width="stretch")
            st.download_button("⬇️ Export CSV", view.to_csv(index=False).encode("utf-8"),
                               file_name=f"netscope_{res['time']:%Y%m%d_%H%M%S}.csv", mime="text/csv")
            if not view.empty:
                pick = st.selectbox("Device details", view["IP Address"].tolist(), key="detail_ip")
                row = view[view["IP Address"] == pick].iloc[0]
                with st.container(border=True):
                    for k in ["Device Name", "Manufacturer", "IP Address", "MAC Address", "Confidence", "Method", "Last Seen"]:
                        st.write(f"**{k}:** {row[k]}")
                    if row["Confidence"] == "Randomized":
                        st.caption("Randomized/private MAC (common on phones): vendor cannot be determined.")
                    elif row["Confidence"] in ("Registry", "Nmap"):
                        st.caption("Vendor = MAC chip maker, not necessarily the device brand or model.")

with tab_hist:
    if not st.session_state.history:
        st.info("No scans yet in this session.")
    else:
        st.dataframe(pd.DataFrame(st.session_state.history), hide_index=True, width="stretch")
        if st.button("Clear history"):
            st.session_state.history = []
            st.rerun()
    st.caption("History is kept for this browser session only; use Export CSV to keep results.")

with tab_help:
    st.markdown("""
- **Where it scans:** the network of the computer running this app, not of your browser.
- **Not guaranteed:** a scan finds devices that answer probes. It is *not* your router's client list; sleeping or
  firewalled devices can be missed.
- **MAC & vendor:** needs ARP on the same subnet (may need Administrator rights on Windows). Phones often use
  randomized MACs, shown as *Unknown*. Vendor is the chip maker, not proof of brand or model.
- **Nothing is uploaded:** no scan data leaves the machine running the app.
""")
