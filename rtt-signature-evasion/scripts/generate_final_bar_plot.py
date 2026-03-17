#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

def generate_bar_plot():
    results_dir = '.'
    scenarios = {
        'Direct connection': 'direct_1000_analysis.csv',
        'Non-evaded 4-hop': 'non_evaded_1000_analysis.csv',
        'Pre-flight evasion 4-hop': 'preflight_1000_v2_analysis.csv'
    }

    data = []
    for label, filename in scenarios.items():
        path = os.path.join(results_dir, filename)
        if not os.path.exists(path):
            print(f"Warning: {path} not found")
            continue
        
        df = pd.read_csv(path)
        median = df.diff_ms.median()
        # Calculate 95th percentile or standard deviation for error bars?
        # Let's use 25th and 75th percentiles (IQR) for a more robust representation
        p25 = df.diff_ms.quantile(0.25)
        p75 = df.diff_ms.quantile(0.75)
        
        data.append({
            'label': label,
            'median': median,
            'p25': p25,
            'p75': p75,
            'n': len(df)
        })

    if not data:
        print("No data found to plot")
        return

    labels = [d['label'] for d in data]
    medians = [d['median'] for d in data]
    lower_errors = [d['median'] - d['p25'] for d in data]
    upper_errors = [d['p75'] - d['median'] for d in data]
    errors = [lower_errors, upper_errors]

    plt.figure(figsize=(10, 6))
    colors = ['royalblue', 'crimson', 'forestgreen']
    
    bars = plt.bar(labels, medians, yerr=errors, capsize=7, color=colors, alpha=0.8, edgecolor='black')
    
    plt.ylabel('Median RTT Gap (TLS - TCP) [ms]', fontsize=12)
    plt.title('Comparison of Median RTT Gaps (1000 Connections)', fontsize=14, fontweight='bold')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add values on top of bars
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 2, f'{yval:.1f} ms', ha='center', va='bottom', fontsize=11, fontweight='bold')

    plt.tight_layout()
    output_path = 'final_comparison_bar.png'
    plt.savefig(output_path, dpi=150)
    print(f"Successfully saved bar plot to {output_path}")

if __name__ == '__main__':
    generate_bar_plot()
