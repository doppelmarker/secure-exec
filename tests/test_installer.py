"""Install-phase integration tests (heavyweight: proxy + volumes + installer).

Marked `installer`; skip with `-m "not installer"`.
"""
import subprocess

import pytest

pytestmark = pytest.mark.installer


def test_install_then_use(install_in_sandbox, user_volume, run_in_sandbox):
    vol = user_volume()
    assert install_in_sandbox(vol, "six", mode="wheel").ok

    r = run_in_sandbox("import six; print('SIX', six.__version__)", volume=vol)
    assert r.ok, r
    assert "SIX" in r.stdout, r


def test_user_venv_replaces_default(install_in_sandbox, user_volume, run_in_sandbox):
    vol = user_volume()
    assert install_in_sandbox(vol, "six", mode="wheel").ok

    r = run_in_sandbox(
        """
        import importlib.util as u
        print('NUMPY', u.find_spec('numpy') is not None)
        print('SIX', u.find_spec('six') is not None)
        """,
        volume=vol,
    )
    assert r.ok, r
    assert "NUMPY False" in r.stdout, r
    assert "SIX True" in r.stdout, r


def test_exec_has_no_network_with_venv(install_in_sandbox, user_volume, run_in_sandbox):
    vol = user_volume()
    assert install_in_sandbox(vol, "six", mode="wheel").ok

    r = run_in_sandbox(
        """
        import socket
        s = socket.socket(); s.settimeout(3)
        s.connect(("1.1.1.1", 53)); print("CONNECTED")
        """,
        volume=vol,
    )
    assert not r.ok, r
    assert "CONNECTED" not in r.stdout


def test_venv_readonly_in_exec(install_in_sandbox, user_volume, run_in_sandbox):
    vol = user_volume()
    assert install_in_sandbox(vol, "six", mode="wheel").ok

    r = run_in_sandbox('open("/venv/site/pwned", "w").write("x"); print("WROTE")',
                       volume=vol)
    assert not r.ok, r
    assert "WROTE" not in r.stdout
    assert "Read-only file system" in r.error or "Permission denied" in r.error, r


def test_install_from_non_pypi_index_is_blocked(install_in_sandbox, user_volume):
    # pip pointed at a non-allow-listed index must fail: the proxy only permits
    # pypi.org + files.pythonhosted.org, enforced at the network layer. Low pip
    # retries/timeout so the blocked attempt fails fast.
    res = install_in_sandbox(
        user_volume(), "six", mode="wheel",
        index_url="https://example.com/simple",
        extra_env={"SE_PIP_RETRIES": "0", "SE_PIP_TIMEOUT": "5"},
        timeout=60,
    )
    assert not res.ok, res


def test_wheel_mode_rejects_sdist_only(install_in_sandbox, user_volume):
    res = install_in_sandbox(user_volume(), "sgmllib3k", mode="wheel")
    assert not res.ok, res
    msg = (res.stdout + res.stderr).lower()
    assert "no binary" in msg or "could not find a version" in msg, res


def test_wheel_image_has_no_compiler(installer_image):
    p = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "sh", installer_image,
         "-c", "command -v gcc >/dev/null && echo HAS_GCC || echo NO_GCC"],
        capture_output=True, text=True, timeout=30,
    )
    assert "NO_GCC" in p.stdout, p.stdout