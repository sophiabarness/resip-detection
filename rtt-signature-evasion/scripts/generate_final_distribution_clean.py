import csv
import os
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

# Use the directory where CSVs are located
RESULTS_DIR = Path('.')
OUTPUT_PATH = RESULTS_DIR / "final_distribution_clean.png"
THRESHOLD_MS = 50

def load_values(filename):
    values = []
    path = RESULTS_DIR / filename
    if not path.exists():
        print(f"Warning: {path} not found")
        return np.array([])
        
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            values.append(float(row["diff_ms"]))
    return np.array(values)

def main():
    series = [
        ("Direct Baseline", "direct_1000_analysis.csv", "#2ecc71"),
        ("4-Hop Relay (No Evasion)", "non_evaded_1000_analysis.csv", "#e74c3c"),
        ("4-Hop Relay (Pre-flight Evasion)", "preflight_1000_v2_analysis.csv", "#3498db"),
    ]

    fig, axes = plt.subplots(3, 1, figsize=(6, 10), sharex=True, sharey=True)

    bins = np.arange(-50, 301, 5)

    for ax, (title, filename, color) in zip(axes, series):
        values = load_values(filename)
        if len(values) == 0:
            continue
            
        clipped = values[(values >= -50) & (values <= 300)]
        median = float(np.median(values))

        ax.hist(clipped, bins=bins, color=color, alpha=0.8, edgecolor="white")
        ax.axvline(THRESHOLD_MS, color="orange", linestyle="--", linewidth=2, label="50 ms threshold")
        ax.axvline(median, color="black", linestyle=":", linewidth=2, label=f"median = {median:.2f} ms")
        ax.set_title(title, fontsize=13, fontweight="bold")
        ax.set_xlabel("RTT Gap (ms)")
        ax.set_xlim(-50, 300)
        ax.grid(axis="y", linestyle=":", alpha=0.35)
        ax.legend(fontsize=9, frameon=True)

    axes[0].set_ylabel("Connection Count")
    axes[1].set_ylabel("Connection Count")
    axes[2].set_ylabel("Connection Count")
    
    plt.tight_layout(h_pad=1.5)
    plt.savefig(OUTPUT_PATH, dpi=300)
    print(f"Saved {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
