# 🛡️ Aegis - Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Security](https://img.shields.io/badge/Security-Blue%20Team-red)
![Dashboard](https://img.shields.io/badge/Dashboard-Streamlit-green)

**Aegis** is a lightweight, Python-based Network Intrusion Detection System (NIDS) designed to detect **TCP SYN Flood** attacks and **Port Scanning** activities in real-time. It features a live **Streamlit Dashboard** to visualize threat data, attacker IPs, and attack frequencies.

## 🚀 Key Features

* **🔍 Real-Time Packet Sniffing:** Monitors network traffic using `Scapy` to detect anomalies.
* **🚨 Threat Detection:** Analyzes TCP Handshakes to identify suspicious SYN requests (Port Scanning / DoS).
* **📊 Live Dashboard:** Visualizes attack telemetry, unique attackers, and incident timelines via a web interface.
* **📝 Event Logging:** detailed attack logs are saved to `alerts.csv` for forensic analysis.

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/Aegis-NIDS.git](https://github.com/YOUR_USERNAME/Aegis-NIDS.git)
    cd Aegis-NIDS
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Npcap Requirement (Windows Only):**
    * Download and install [Npcap](https://npcap.com/#download).
    * **Important:** Ensure you check the box *"Install Npcap in WinPcap API-compatible Mode"* during installation.

## 💻 Usage

To run the system, you need to open two separate terminals:

**Terminal 1: The Detection Engine (Backend)**
Starts sniffing the network and logging attacks.
```bash
python main.py
```
**Terminal 2: The Dashboard (Frontend) Launches the web interface for real-time monitoring.**
```bash
streamlit run dashboard.py
```

## Project Structure

```bash
Aegis-NIDS/
│
├── main.py          # Network sniffer & detection engine (Backend)
├── dashboard.py     # Streamlit visualization dashboard (Frontend)
├── attacker.py      # Attack simulation script (Red Team Tool)
├── alerts.csv       # Log file for attack data
└── requirements.txt # Project dependencies
```

## ⚠️ Disclaimer
This tool is developed for educational and defensive purposes only. Do not use this tool on networks you do not own or have explicit permission to test.
