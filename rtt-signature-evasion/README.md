# RESIP Detection and Evasion Code

This repository contains the source code used for the research project on Residential Proxy (RESIP) detection and evasion. The code is organized into three main categories: proxies, analysis, and orchestration scripts.

## Directory Structure

### `proxies/`
Core implementations of the relay and evasion mechanisms discussed in the paper.
- `chained_proxy.py`: Implementation of the multi-hop relay architecture.
- `cloak_daemon.py`: The "Deep Cloak" timing manipulation daemon (intercepts and delays TCP handshakes via IPC).
- `splice_proxy.py`: A high-performance proxy variant using TCP splicing.

### `analysis/`
Scripts for processing raw network captures (PCAPs) and generating statistical results.
- `analyze_experiment.py`: Main script for extracting RTT metrics (TCP vs TLS) from PCAPs.

### `scripts/`
Measurement tools, orchestration scripts, and server configuration.
- `client.py`: The measurement client used to perform RTT-instrumented TLS handshakes.
- `run_global_benchmark.sh`: Orchestrates the global baseline measurement (Section 4).
- `run_evasion_benchmark.sh`: Runs the multi-region evasion experimental matrix (Section 5.1).
- `setup_global_servers.sh` / `configure_servers.sh`: Automated GCP infrastructure setup.
- `relay_setup.sh`: Utility for toggling relay modes and starting daemons.

## Usage Overview
1. **Infrastructure**: Deploy the relay and server instances using `setup_global_servers.sh`.
2. **Measurement**: Run the target experiment using the appropriate shell script. For the global benchmark, provide the proxy credentials via an environment variable:
   ```bash
   export PROXY_URL="http://user:pass@host:port"
   ./scripts/run_global_benchmark.sh
   ```
3. **Evasion**: Enable timing manipulation by running `cloak_daemon.py` on the relay node before starting the client.
4. **Analysis**: Process the generated PCAPs using `analyze_experiment.py`.

## Requirements
- Python 3.8+
- Scapy (for packet manipulation in `cloak_daemon.py`)
- Tshark / Wireshark (for analysis scripts)
- Matplotlib / NumPy (for plotting)
