import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt

# Usage:
#   python plot_fav_limit.py fav_detection_limit_lt64_skip128.csv
#
# Wide CSV format (recommended):
#   Bytes,TXT,ZIP,DOCX,PDF
#   0,0,0,0,0
#   1,95,100,100,100
#   ...

def main():
    parser = argparse.ArgumentParser(
        description="Plot FAV detection ratio vs encrypted bytes (paper-friendly)."
    )
    parser.add_argument("csv", help="Input CSV (wide or long format).")
    parser.add_argument("--title", default="", help="Optional title.")
    args = parser.parse_args()

    csv_path = args.csv
    base, _ = os.path.splitext(csv_path)
    output_pdf = f"{base}.pdf"

    # --- Style settings (match your existing plot style) ---
    plt.rcParams.update({
        "font.size": 8,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
        "lines.linewidth": 0.9,
        "lines.markersize": 3.0,
    })

    df = pd.read_csv(csv_path)

    # Detect format: wide vs long
    cols = [c.strip() for c in df.columns]
    df.columns = cols

    is_long = set(cols) >= {"Bytes", "Detector", "Detection Ratio"}
    is_wide = "Bytes" in cols and any(c in cols for c in ["TXT", "ZIP", "DOCX", "PDF"])

    fig, ax = plt.subplots(figsize=(3.0, 2.2))

    # --- Plot ---
    if is_wide:
        # Ensure sorted by Bytes
        df = df.sort_values("Bytes")

        series_order = ["TXT", "ZIP", "DOCX", "PDF"]
        markers = {"TXT": "o", "ZIP": "s", "DOCX": "^", "PDF": "D"}  # distinct markers

        for name in series_order:
            if name in df.columns:
                ax.plot(df["Bytes"], df[name], marker=markers.get(name, "o"),
                        linestyle="-", label=name)

        xticks = df["Bytes"].tolist()

    elif is_long:
        # Long format rows: Bytes, Detector, Detection Ratio
        df = df.rename(columns={"Detection Ratio": "Detection_Ratio"})
        df = df.sort_values("Bytes")

        series_order = ["TXT", "ZIP", "DOCX", "PDF"]
        markers = {"TXT": "o", "ZIP": "s", "DOCX": "^", "PDF": "D"}

        for name in series_order:
            sub = df[df["Detector"] == name]
            if not sub.empty:
                ax.plot(sub["Bytes"], sub["Detection_Ratio"],
                        marker=markers.get(name, "o"),
                        linestyle="-",
                        label=name)

        xticks = sorted(df["Bytes"].unique().tolist())

    else:
        raise ValueError(
            "Unrecognized CSV format.\n"
            "Use either:\n"
            "  (A) wide: Bytes,TXT,ZIP,DOCX,PDF\n"
            "  (B) long: Bytes,Detector,Detection Ratio"
        )

    # --- Labels / axes ---
    ax.set_xlabel("Encrypted bytes")
    ax.set_ylabel("Detection rate (%)")

    ax.set_xticks(xticks)
    ax.set_ylim(-5, 105)

    ax.grid(True, linestyle=":", linewidth=0.5)

    if args.title.strip():
        ax.set_title(args.title.strip())

    # --- Legend: outside, below (like your script) ---
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.22),
        ncol=4,
        frameon=False,
        handlelength=1.6,
        columnspacing=1.0,
    )

    # --- Layout tuning (space for legend) ---
    fig.tight_layout()
    fig.subplots_adjust(bottom=0.30)

    fig.savefig(output_pdf)
    plt.close(fig)
    print(f"Saved: {output_pdf}")

if __name__ == "__main__":
    main()
