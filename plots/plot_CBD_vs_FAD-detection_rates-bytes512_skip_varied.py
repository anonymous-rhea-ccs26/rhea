import pandas as pd
import matplotlib.pyplot as plt

# --- Style settings ---
plt.rcParams.update({
    "font.size": 8,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
    "lines.linewidth": 1.0,
})

# 1) Load data from CSV
df = pd.read_csv("CBD_vs_FAD-detection_rates-bytes512_skip_varied.csv")

# 2) Create figure (size tuned for paper, adjust if needed)
plt.figure(figsize=(3.0, 2.2))  # width x height in inches

# 3) Plot each series
plt.plot(df["Skip"], df["FAV"],
         marker="o", linestyle="-", label="FAV")
plt.plot(df["Skip"], df["Entropy"],
         marker="s", linestyle="-", label="Entropy")
plt.plot(df["Skip"], df["Chi2"],
         marker="^", linestyle="-", label="Chi²")

# 4) Axes labels, ticks, limits
plt.xlabel("Skipped bytes")
plt.ylabel("Detection rate (%)")

# Use your exact x locations
plt.xticks([0, 128, 256, 384, 512, 640, 768, 896, 1024])

# We know y is in [0, 100]
plt.ylim(-5, 105)

# Optional: light grid for readability
plt.grid(True, linestyle=":", linewidth=0.5)

# Legend (top-left; tweak as needed)
plt.legend(loc="lower left", fontsize=7)

# 5) Tight layout to reduce margins
plt.tight_layout()

# 6) Save as PDF (for CCS) and PNG (for quick viewing)
plt.savefig("CBD_vs_FAD-detection_rates-bytes512_skip_varied.pdf")
plt.savefig("CBD_vs_FAD-detection_rates-bytes512_skip_varied.png", dpi=300)

print("Saved: CBD_vs_FAD-detection_rates-bytes512_skip_varied.pdf and CBD_vs_FAD-detection_rates-bytes512_skip_varied.png")
