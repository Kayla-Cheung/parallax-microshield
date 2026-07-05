"""
PyParallax CLI 测试 — 验证 `parallax` 命令入口同步与功能正确。
"""

import subprocess
import sys
from pathlib import Path

import pytest

from pyparallax.cli import main, build_parser


# ============================================================================
# 入口同步验证
# ============================================================================

class TestCLIEntryPoint:
    """三处 CLI 入口声明必须一致且可调用"""

    def test_main_callable(self):
        """pyparallax.cli.main 必须存在且可调用"""
        assert callable(main)

    def test_parser_builds(self):
        """argparse parser 必须能构造"""
        parser = build_parser()
        assert parser.prog == "parallax"

    def test_version_flag(self, capsys):
        """--version 应输出 0.2.0"""
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["--version"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "0.2.0" in out

    def test_installed_console_script(self):
        """pip install -e . 后 `parallax` 命令必须可调用"""
        # 用 --version 验证 console_script 真实安装成功
        result = subprocess.run(
            ["parallax", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "0.2.0" in result.stdout


# ============================================================================
# 子命令功能验证
# ============================================================================

class TestSubcommands:
    """run / doctor 子命令必须正常工作"""

    def test_doctor(self, capsys, tmp_path, monkeypatch):
        """parallax doctor 应输出环境诊断"""
        monkeypatch.setenv("PARALLAX_ROOT", str(tmp_path / ".parallax"))
        from pyparallax.core import reset_chronicle, new_session
        reset_chronicle()
        new_session()

        rc = main(["doctor"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "parallax 0.2.0" in out
        assert "chronicle root:" in out
        assert "ok" in out

    def test_run_executes_script(self, tmp_path, monkeypatch):
        """parallax run <script.py> 应零侵入执行目标脚本"""
        monkeypatch.setenv("PARALLAX_ROOT", str(tmp_path / ".parallax"))

        script = tmp_path / "agent.py"
        script.write_text(
            "import sys\n"
            "print('hello from agent')\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )

        rc = main(["run", str(script)])
        assert rc == 0

    def test_run_propagates_exit_code(self, tmp_path, monkeypatch):
        """子脚本的退出码必须透传"""
        monkeypatch.setenv("PARALLAX_ROOT", str(tmp_path / ".parallax"))

        script = tmp_path / "fail.py"
        script.write_text(
            "import sys\n"
            "sys.exit(42)\n",
            encoding="utf-8",
        )

        rc = main(["run", str(script)])
        assert rc == 42

    def test_run_missing_script(self, tmp_path, monkeypatch):
        """不存在的脚本应返回错误码 2"""
        monkeypatch.setenv("PARALLAX_ROOT", str(tmp_path / ".parallax"))
        rc = main(["run", str(tmp_path / "nope.py")])
        assert rc == 2

    def test_run_passes_args_through(self, tmp_path, monkeypatch):
        """额外参数必须透传给子脚本"""
        monkeypatch.setenv("PARALLAX_ROOT", str(tmp_path / ".parallax"))

        script = tmp_path / "echo_args.py"
        script.write_text(
            "import sys\n"
            "args = sys.argv[1:]\n"
            "print('ARGS:', args)\n"
            "assert args == ['--foo', 'bar'], args\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )

        rc = main(["run", str(script), "--foo", "bar"])
        assert rc == 0

    def test_run_rejects_non_py(self, tmp_path, monkeypatch):
        """非 .py 脚本应拒绝"""
        monkeypatch.setenv("PARALLAX_ROOT", str(tmp_path / ".parallax"))
        sh = tmp_path / "agent.sh"
        sh.write_text("#!/bin/bash\necho hi\n")
        rc = main(["run", str(sh)])
        assert rc == 2


# ============================================================================
# 版本号一致性验证
# ============================================================================

class TestVersionSync:
    """三处版本号必须一致：pyproject.toml / __init__.py / plugin.json"""

    def test_versions_aligned(self):
        import json
        root = Path(__file__).parent.parent

        # __init__.py
        import pyparallax
        init_ver = pyparallax.__version__

        # pyproject.toml
        toml_text = (root / "pyproject.toml").read_text(encoding="utf-8")
        import re
        m = re.search(r'^version\s*=\s*"([^"]+)"', toml_text, re.MULTILINE)
        assert m, "pyproject.toml version not found"
        toml_ver = m.group(1)

        # plugin.json
        plugin = json.loads((root / "plugin.json").read_text(encoding="utf-8"))
        plugin_ver = plugin["version"]

        assert init_ver == toml_ver == plugin_ver, (
            f"version mismatch: __init__={init_ver}, "
            f"pyproject={toml_ver}, plugin.json={plugin_ver}"
        )
