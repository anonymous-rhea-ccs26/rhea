# Grab 4 KiB around the offset; adjust length to match your SAWA window scale (e.g., 512, 2048…)
dd if=$1 of=/tmp/blk.bin bs=1 skip=$2 count=$3 status=none

python3 - <<'PY'
import sys, math
from collections import Counter
b=open("/tmp/blk.bin","rb").read()
n=len(b)
freq=Counter(b)
exp=n/256 if n else 1
chi2=sum(((freq.get(i,0)-exp)**2)/(exp if exp>0 else 1) for i in range(256))
ascii_ratio=sum(1 for x in b if 9<=x<=13 or 32<=x<=126)/n if n else 0
token_ratio=sum(1 for x in b if x in b"{}[]()<>=/,:;\"' \t\r\n")/n if n else 0
print(f"len={n} chi2={chi2:.1f} ascii={ascii_ratio:.3f} token={token_ratio:.3f}")
PY
