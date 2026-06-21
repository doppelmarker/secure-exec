"""Positive tests: the sandbox must still run legitimate workloads."""


def test_hello_world(run_in_sandbox):
    r = run_in_sandbox("print('hello from sandbox')")
    assert r.ok, r
    assert "hello from sandbox" in r.stdout


def test_basic_compute(run_in_sandbox):
    r = run_in_sandbox("print(sum(i*i for i in range(1000)))")
    assert r.ok, r
    assert "332833500" in r.stdout


def test_numpy_works(run_in_sandbox):
    r = run_in_sandbox("""
        import numpy as np
        a = np.arange(12).reshape(3, 4)
        print(int(a.sum()), a.dtype)
    """)
    assert r.ok, r
    assert "66" in r.stdout


def test_pandas_works(run_in_sandbox):
    r = run_in_sandbox("""
        import pandas as pd
        df = pd.DataFrame({"x": [1, 2, 3], "y": [4, 5, 6]})
        print(int(df["x"].sum()), int((df["x"] * df["y"]).sum()))
    """)
    assert r.ok, r
    assert "6 32" in r.stdout


def test_numpy_pandas_together(run_in_sandbox):
    r = run_in_sandbox("""
        import numpy as np
        import pandas as pd
        s = pd.Series(np.linspace(0, 1, 5))
        print(round(float(s.mean()), 3))
    """)
    assert r.ok, r
    assert "0.5" in r.stdout