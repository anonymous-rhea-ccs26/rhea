import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt

# Usage:
# python plot_detection.py bytes_varied_skip128-txt_only_data.csv

# ---------------------------
# CLI arguments
# ---------------------------
parser = argparse.ArgumentParser(
    description="Plot detection rates from a CSV file and save as PDF."
)
parser.add_argument(
    "csv",
    help="Input CSV file (e.g., bytes_varied_skip128-txt_only_data.csv)"
)
args = parser.parse_args()

csv_path = args.csv

# ---------------------------
# Output filename (PDF only)
# ---------------------------
base, _ = os.path.splitext(csv_path)
output_pdf = f"{base}.pdf"

# ---------------------------
# Style settings (paper-friendly)
# ---------------------------
plt.rcParams.update({
    "font.size": 8,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
    "lines.linewidth": 0.9,
    "lines.markersize": 3.0,
})

# ---------------------------
# Load data
# ---------------------------
df = pd.read_csv(csv_path)

# ---------------------------
# Plot
# ---------------------------
fig, ax = plt.subplots(figsize=(3.0, 2.2))

ax.plot(df["Bytes"], df["FAV"],
        marker="o", linestyle="-", label="FAV")
ax.plot(df["Bytes"], df["Entropy"],
        marker="s", linestyle="-", label="Entropy")
ax.plot(df["Bytes"], df["Chi2"],
        marker="^", linestyle="-", label="Chi²")

ax.set_xlabel("Encrypted bytes")
ax.set_ylabel("Detection rate (%)")

ax.set_xticks([0, 64, 128, 192, 256, 320, 384, 448, 512])
ax.set_ylim(-5, 105)

ax.grid(True, linestyle=":", linewidth=0.5)

# ---------------------------
# Legend: outside, below (KEY CHANGE)
# ---------------------------
ax.legend(
    loc="upper center",
    bbox_to_anchor=(0.5, -0.22),  # center, below axes
    ncol=3,
    frameon=False,
    handlelength=1.6,
    columnspacing=1.0,
)

# ---------------------------
# Layout tuning (make room for legend)
# ---------------------------
fig.tight_layout()
fig.subplots_adjust(bottom=0.30)

# ---------------------------
# Save PDF only
# ---------------------------
fig.savefig(output_pdf)
plt.close(fig)

print(f"Saved: {output_pdf}")
