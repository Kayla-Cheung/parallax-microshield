"""
PyParallax CLI — `parallax` 命令行入口

实现 ROADMAP Sprint 5 承诺的零侵入 CLI 包装：
    parallax run <script.py> [args...]

机制：
  1. fork 子进程执行目标脚本
  2. 父进程在子进程执行前调用 new_session() 确保干净会话边界
  3. 子进程的 stdout/stderr 透传到父进程
  4. 退出码透传

这样任何已有的 Python agent 脚本无需改一行代码，就能跑在 Parallax
Shield 网关保护下（前提是脚本内的危险操作已用 @parallax_shield 装饰）。
"""

import argparse
import subprocess  # nosec B404  # 安全见下方 _cmd_run 文档
import sys
from pathlib import Path

from . import __version__
from .core import new_session, get_session, TrustLabel


def _cmd_run(args) -> int:
    """`parallax run <script.py>` — 零侵入包装执行"""
    script = Path(args.script).expanduser().resolve()
    if not script.exists():
        print(f"parallax: script not found: {script}", file=sys.stderr)
        return 2
    if not script.suffix == ".py":
        print(f"parallax: only .py scripts supported, got: {script.suffix}",
              file=sys.stderr)
        return 2

    # 父进程建立干净会话边界（虽然子进程是独立 Python 解释器，
    # 但若未来支持 in-process 执行，此调用确保起点干净）
    new_session()

    # 透传额外参数给脚本
    # 安全保证：
    #   - shell=False（默认）：不经过 shell，无命令注入风险
    #   - script 已校验为 .py 文件且存在
    #   - script_args 透传到子 Python 进程的 sys.argv，由脚本自身负责解析
    #     （这是 ROADMAP 承诺的"零侵入"语义，必须支持任意 args 透传）
    cmd = [sys.executable, str(script), *args.script_args]
    print(f"parallax: executing {script} under Tier 0 Shield", file=sys.stderr)
    print(f"parallax: session label = {get_session().label.name}", file=sys.stderr)

    try:
        proc = subprocess.run(  # nosec B603  # shell=False, 见上方安全保证
            cmd, check=False, shell=False,
        )
        return proc.returncode
    except KeyboardInterrupt:
        print("\nparallax: interrupted", file=sys.stderr)
        return 130


def _cmd_doctor(args) -> int:
    """`parallax doctor` — 自检环境与配置"""
    from .core import get_chronicle
    print(f"parallax {__version__}")
    print(f"python {sys.version.split()[0]}")
    chron = get_chronicle()
    print(f"chronicle root: {chron.root}")
    print(f"  trash:      {chron.trash} ({len(list(chron.trash.iterdir()))} items)")
    print(f"  snapshots:  {chron.snapshots} ({len(list(chron.snapshots.iterdir()))} items)")
    print(f"  audit_log:  {chron.audit_log} ({'exists' if chron.audit_log.exists() else 'new'})")
    print(f"session label: {get_session().label.name}")
    print("ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="parallax",
        description="PyParallax Tier 0 Shield — zero-trust gateway for AI agents",
    )
    parser.add_argument("--version", action="version", version=f"parallax {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run a Python script under Parallax Shield")
    run.add_argument("script", help="Path to the .py script to execute")
    run.add_argument("script_args", nargs=argparse.REMAINDER,
                     help="Arguments to pass through to the script")
    run.set_defaults(func=_cmd_run)

    doc = sub.add_parser("doctor", help="Show environment diagnostics")
    doc.set_defaults(func=_cmd_doctor)
    return parser


def main(argv=None) -> int:
    """CLI 入口。返回退出码。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
