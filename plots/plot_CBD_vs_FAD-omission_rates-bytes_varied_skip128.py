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

# 1) Load CSV
df = pd.read_csv("CBD_vs_FAD-omission_rates-bytes_varied_skip128.csv")

# 2) Figure size for CCS (same as detection figure)
plt.figure(figsize=(3.0, 2.2))

# 3) Plot each method
plt.plot(df["Bytes"], df["FAV"],
         marker="o", linestyle="-", label="FAV")
plt.plot(df["Bytes"], df["Entropy"],
         marker="s", linestyle="-", label="Entropy")
plt.plot(df["Bytes"], df["Chi2"],
         marker="^", linestyle="-", label="Chi²")

# 4) Axes labels & ticks
plt.xlabel("Encrypted bytes")
plt.ylabel("Omission rate (%)")   # consistent naming

# fixed tick positions
plt.xticks([0, 64, 128, 192, 256, 320, 384, 448, 512])

plt.ylim(-5, 105)

# Grid for readability (same as previous plot)
plt.grid(True, linestyle=":", linewidth=0.5)

# Legend placement
plt.legend(loc="upper right")

# 5) Tight layout for publication
plt.tight_layout()

# 6) Save in CCS-friendly PDF + PNG
plt.savefig("CBD_vs_FAD-omission_rates-bytes_varied_skip128.pdf")
plt.savefig("CBD_vs_FAD-omission_rates-bytes_varied_skip128.png", dpi=300)

print("Saved: CBD_vs_FAD-omission_rates-bytes_varied_skip128.pdf and PNG")
