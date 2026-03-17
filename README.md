# Residential Proxy (RESIP) Detection & Evasion: Research Archive

This repository contains the code and data necessary to reproduce the findings in the research paper: **"Residential Proxy Detection"**.

## Directory Structure

### [proxy-traffic-analysis](./proxy-traffic-analysis/)
Contains the logic for characterizing relayed traffic from Honeygain and PacketStream (Section 3.1 of the paper).
- `analyze_pcap.py`: Main script for metadata extraction and analysis.
- `packet_capture_command.txt`: The exact `tcpdump` parameters used for data collection.

### [badpass-validation](./badpass-validation/)
Contains the code used to validate the RTT-gap detection mechanism reported in Section 3.2.
- `run_global_benchmark.sh`: automated script for regional benchmark testing.
- `client.py`: Load-generation client for Direct and Proxy connections.
- `analyze_experiment.py`: Extracts TCP and TLS RTTs to compute the gap.

### [rtt-signature-evasion](./rtt-signature-evasion/)
Contains the code for the pre-flight evasion mechanism and final benchmark results.

#### [src/](./rtt-signature-evasion/src/)
- `splice_proxy_preflight.py`: Proxy interceptor implementing the Fake SOCKS Success probe.
- `cloak_daemon_preflight.py`: Daemon for delaying TCP ACKs based on probe results.

#### [scripts/](./rtt-signature-evasion/scripts/)
- `run_evasion_benchmark.sh`: Benchmarks the 4-hop pre-flight evasion setup.
- `generate_final_bar_plot.py`: Generates the comparative RTT gap bar chart.
- `generate_final_distribution_clean.py`: Replicates the high-fidelity distribution histogram.

#### [results/](./rtt-signature-evasion/results/)
- Final 1000-connection PCAPs and CSVs for Direct, Non-Evaded, and Pre-flight benchmarks.

## Reproducibility
To regenerate the paper's final figures using the cached data:
```bash
cd rtt-signature-evasion/scripts
python3 generate_final_bar_plot.py
python3 generate_final_distribution_clean.py
```
