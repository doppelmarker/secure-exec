"""Example legitimate workload — run it through the sandbox:

    docker build -t secure-exec:latest .
    docker run --rm -i \
        --network none --cap-drop ALL \
        --security-opt no-new-privileges --security-opt seccomp=unconfined \
        secure-exec:latest - < examples/numpy_pandas.py
"""
import numpy as np
import pandas as pd

rng = np.random.default_rng(42)
df = pd.DataFrame({
    "group": rng.choice(list("abc"), size=20),
    "value": rng.normal(size=20),
})

summary = df.groupby("group")["value"].agg(["count", "mean", "std"])
print(summary.round(3).to_string())
print("\ntotal rows:", len(df))