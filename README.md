# NetScope

Single-file Streamlit app that discovers devices on a local WiFi/LAN using Nmap and shows IP, MAC,
manufacturer (from the Nmap/IEEE vendor list), hostname and last-seen time. Search, filters, CSV export.

> **Important:** a scan runs on the machine hosting the app. Hosted on Streamlit Cloud/Render/etc. it scans
> *that server's* network, not your home WiFi. To scan your own devices, run it on a PC/Raspberry Pi inside your network.

## Run on Windows
1. Install Python 3.11+ and [Nmap](https://nmap.org/download.html) (keep **Npcap** ticked).
2. Double-click `run.bat` (or: `python -m venv .venv`, `.venv\Scripts\activate`, `pip install -r requirements.txt`, `streamlit run app.py`).
3. Open http://localhost:8501. MAC addresses may need an Administrator terminal.

## Run on Linux / Raspberry Pi
```
sudo apt install nmap
pip install -r requirements.txt
sudo streamlit run app.py     # sudo only if MACs show "Unavailable"
```

## Docker (Linux host, scans the host LAN)
```
docker build -t netscope .
docker run --rm --network host -e NETSCOPE_PASSWORD=change-me netscope
```
(`--network host` is required to see the LAN; it works on Linux hosts only.)

## Password
Set `NETSCOPE_PASSWORD` (env var, or `.streamlit/secrets.toml`, see `secrets.toml.example`). **Always set it
before exposing the app on a domain**: anyone with access could otherwise scan your network.

## Domain access to your home PC
Keep the app running on the PC and use a tunnel, e.g. Cloudflare Tunnel:
`cloudflared tunnel --url http://localhost:8501`, then attach your domain in the Cloudflare dashboard.
Add Cloudflare Access for a second login layer.

## Deploy to GitHub / Streamlit Community Cloud
Push this folder to a GitHub repo, then at share.streamlit.io choose the repo and `app.py`.
`packages.txt` installs Nmap there. It will run, but see the important note above.

## Limits
- Not the router's client list; sleeping/firewalled devices can be missed.
- Phones often use randomized MACs, so vendor shows *Unknown*. Vendor = chip maker, not proof of brand/model.
- No scan data is uploaded anywhere. History is per browser session; use Export CSV to keep results.

## Licenses
Streamlit (Apache-2.0), psutil (BSD-3). Nmap/Npcap are **not bundled**; install them separately under their
own licenses. Add your own LICENSE file for this code.
