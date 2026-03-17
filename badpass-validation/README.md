# badpass-validation

This section contains the code used to validate the RTT-gap detection mechanism across global regions, as reported in Section 3.2 of the paper.

## Key Components
- `run_global_benchmark.sh`: The master script. It iterates through 5 GCP regions (Oregon, SC, Netherlands, Tokyo, Sao Paulo), sets up a temporary `tcpdump` capture on target servers, and executes 1000 pairs of Direct/Proxy connections.
- `client.py`: A Python client that generates high-concurrency HTTPS requests. It supports both `direct` and `proxy` modes.
- `analyze_experiment.py`: A Wireshark-based (`tshark`) analysis script that extracts TCP SYNs and TLS ServerHellos to compute the RTT gap ($\Delta$).

## How to Run
1.  **Set up Servers**: Ensure GCP instances (`resip-server`, `resip-server-east`, etc.) are running and accessible via SSH.
2.  **Configure Proxy**: Set your commercial proxy credentials:
    ```bash
    export PROXY_URL="http://user:pass@host:port"
    ```
3.  **Execute Benchmark**:
    ```bash
    bash run_global_benchmark.sh
    ```
4.  **Results**: PCAP files and analysis graphs will be saved to the `rtt-signature-evasion/results/` folder for final paper analysis.
