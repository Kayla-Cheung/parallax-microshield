"""
PyParallax Core — Tier 0 Shield 网关

参考 OpenParallax (arXiv:2604.12986) 的四层防御范式中的 Tier 0 确定性层：
  1. Adversarial Validation  — Pydantic 全量参数契约校验
  2. Path Containment        — resolve() + is_relative_to 语义校验
  3. IFC Lattice Check       — 统一信任格偏序比较
  4. Chronicle CoW           — 写前快照 + 软删除降级 + 崩溃回滚

设计原则（Saltzer-Schroeder 公理）：
  - Complete Mediation: 每笔跨界动作必经网关，位置参数也校验
  - Monotonic Trust:    会话信任单调上升，无公开 reset，洗白只能开新会话
  - Fail-safe Defaults: 校验失败默认拒绝
  - Policy ≠ Mechanism: 策略（label/op_class）与机制（decorator）分离
"""

import functools
import inspect
import logging
import os
import shutil
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from enum import Enum, IntEnum
from pathlib import Path
from typing import Callable, List, Optional, Type

from pydantic import BaseModel, ValidationError

# 不在模块导入时配置 root logger，把配置权交给宿主
logger = logging.getLogger("pyparallax")


# ============================================================================
# 1. 信任格 (Trust Lattice) — 取代原 ClearanceLevel + IFCTag 两个独立 enum
# ============================================================================

class TrustLabel(IntEnum):
    """统一信任标签格：PUBLIC ≤ INTERNAL ≤ CONFIDENTIAL ≤ RESTRICTED

    会话携带 current_label（单调上升），操作声明 max_session_label（容忍上限）。
    决策：session.label <= max_session_label 才放行。
    """
    PUBLIC = 1          # 干净会话
    INTERNAL = 2        # 接触过内部数据
    CONFIDENTIAL = 3    # 接触过敏感数据
    RESTRICTED = 4      # 接触过外部不可信/有毒数据（最高风险）


class OpClass(Enum):
    """操作可逆性分类 — 决定 Chronicle 处理方式"""
    READ = "read"                       # 只读，无副作用
    WRITE_REVERSIBLE = "write_rev"      # 覆写本地文件，写前快照
    WRITE_DESTRUCTIVE = "write_destr"   # rm/drop 等，强制降级为 mv 到 trash
    SIDE_EFFECT_IRREVERSIBLE = "side_eff"  # 网络等不可逆操作，要求 session=PUBLIC


# ============================================================================
# 2. 异常分类 — 取代单一 ParallaxSecurityException
# ============================================================================

class ParallaxSecurityException(Exception):
    """网关熔断基类"""
    pass


class ValidationViolation(ParallaxSecurityException):
    """Tier 0a 失败：Pydantic schema 校验未通过"""
    pass


class PathContainmentViolation(ParallaxSecurityException):
    """Tier 0b 失败：路径越界"""
    pass


class IFCViolation(ParallaxSecurityException):
    """Tier 0c 失败：信息流控制熔断（会话被污染后越权）"""
    pass


class RollbackFailure(ParallaxSecurityException):
    """Chronicle 回滚失败"""
    pass


# ============================================================================
# 3. 会话上下文 — contextvars 替代 threading.local，无公开 reset
# ============================================================================

class SessionContext:
    """会话信任上下文。

    信任状态的本质是"会话内曾接触过什么数据"——这是历史事实，不可篡改。
    因此 taint 单调上升，无公开 reset()。洗白的唯一合法入口是 new_session()，
    它由请求边界中间件调用，物理上无法被 Agent 在自己的调用栈里触达。
    """

    def __init__(self) -> None:
        self._label = TrustLabel.PUBLIC
        # append-only 历史事件，便于审计与 IFCViolation 报告
        self._taint_history: List[tuple] = []

    @property
    def label(self) -> TrustLabel:
        return self._label

    @property
    def taint_history(self) -> List[tuple]:
        return list(self._taint_history)

    def taint(self, label: TrustLabel, source: str = "unknown") -> None:
        """单调升权 + append-only 历史。降级只能开新会话。"""
        if label.value > self._label.value:
            self._label = label
            logger.warning(
                "[IFC] Session tainted -> %s (source: %s)", label.name, source
            )
        self._taint_history.append((time.time(), label.name, source))

    def can_execute(self, max_session_label: TrustLabel) -> bool:
        """偏序比较：当前 label 不超过操作容忍上限才放行"""
        return self._label <= max_session_label


_session_var: ContextVar["SessionContext"] = ContextVar("parallax_session")


def get_session() -> SessionContext:
    """获取当前会话（contextvars，asyncio + 线程双安全）。

    首次调用会自动创建一个会话，向后兼容简单脚本场景。
    """
    try:
        return _session_var.get()
    except LookupError:
        sess = SessionContext()
        _session_var.set(sess)
        return sess


def new_session() -> SessionContext:
    """请求边界创建新会话——洗白的唯一合法入口。

    应在 ASGI/CLI 请求边界调用，不在 Agent 调用栈内。
    """
    sess = SessionContext()
    _session_var.set(sess)
    return sess


@contextmanager
def tainted_reader(label: TrustLabel, source: str = "unknown"):
    """读外部数据的自动 taint 入口。

    信任单调性：离开 with 块**不还原** taint。这是关键设计——
    若 with 退出后还原，Agent 只需把破坏操作放到 with 块外即可绕过 IFC。
    """
    get_session().taint(label, source)
    yield


# ============================================================================
# 4. Chronicle — 写前快照 + 软删除降级（兑现 SKILL.md 的承诺）
# ============================================================================

# 项目根目录启发式标记（对齐 .cursor/ .trae/ .git/ 等 vibe coding 约定）
_PROJECT_ROOT_MARKERS = (
    ".git", "pyproject.toml", "package.json", ".cursor", ".trae", ".parallax",
)


def _is_project_root(p: Path) -> bool:
    return any((p / m).exists() for m in _PROJECT_ROOT_MARKERS)


class Chronicle:
    """轻量级容灾存储——写前快照 + 软删除。

    储存位置（vibe coding 用户习惯，对齐 .cursor/.trae/.git 约定）：
      优先级：$PARALLAX_ROOT 环境变量 > ./.parallax/ > ~/.parallax/

    目录布局：
      .parallax/
        ├── trash/             # 软删除目标 (mv 替代 rm)
        ├── snapshots/         # CoW 写前快照
        └── audit.log          # taint 事件 + 网关决策
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = root.resolve() if root else self._discover_root()
        self.trash = self.root / "trash"
        self.snapshots = self.root / "snapshots"
        self.audit_log = self.root / "audit.log"
        self.root.mkdir(parents=True, exist_ok=True)
        self.trash.mkdir(exist_ok=True)
        self.snapshots.mkdir(exist_ok=True)

    @staticmethod
    def _discover_root() -> Path:
        env = os.environ.get("PARALLAX_ROOT")
        if env:
            return Path(env).expanduser()
        # 当前目录或其祖先若含项目标记，用 ./.parallax/
        cur = Path.cwd()
        for p in [cur, *cur.parents]:
            if _is_project_root(p):
                return p / ".parallax"
        return Path.home() / ".parallax"

    def _ts(self) -> str:
        return time.strftime("%Y%m%d_%H%M%S") + f"_{uuid.uuid4().hex[:6]}"

    def _audit(self, msg: str) -> None:
        with open(self.audit_log, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}\n")
        logger.info("[CHRONICLE] %s", msg)

    def snapshot(self, target: Path) -> Optional[Path]:
        """写前快照。目标不存在返回 None。"""
        target = target.resolve()
        if not target.exists():
            return None
        ts = self._ts()
        if target.is_file():
            bak = self.snapshots / f"{ts}_{target.name}.bak"
            shutil.copy2(target, bak)
            self._audit(f"SNAPSHOT {target} -> {bak}")
            return bak
        if target.is_dir():
            bak = self.snapshots / f"{ts}_{target.name}"
            shutil.copytree(target, bak)
            self._audit(f"SNAPSHOT_DIR {target} -> {bak}")
            return bak
        return None

    def soft_delete(self, target: Path) -> Path:
        """软删除：mv 到 trash，永不物理删除。"""
        target = target.resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        ts = self._ts()
        dest = self.trash / f"{ts}_{target.name}"
        shutil.move(str(target), str(dest))
        self._audit(f"SOFT_DELETE {target} -> {dest}")
        return dest

    def restore(self, snapshot: Path, target: Path) -> None:
        """从快照还原。"""
        snapshot = snapshot.resolve()
        target = target.resolve()
        if snapshot.is_file():
            shutil.copy2(snapshot, target)
        elif snapshot.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(snapshot, target)
        else:
            raise FileNotFoundError(snapshot)
        self._audit(f"RESTORE {snapshot} -> {target}")


_chronicle: Optional[Chronicle] = None


def get_chronicle() -> Chronicle:
    """全局 Chronicle 单例（懒加载）"""
    global _chronicle
    if _chronicle is None:
        _chronicle = Chronicle()
    return _chronicle


def reset_chronicle() -> None:
    """测试用：重置全局 Chronicle 单例"""
    global _chronicle
    _chronicle = None


# ============================================================================
# 5. Path Containment — 语义校验，取代 regex 黑名单
# ============================================================================

def check_path_containment(
    target: Path, allowed_roots: List[Path]
) -> Path:
    """Tier 0b：路径必须在某个授权根目录内（resolve + is_relative_to）。

    拒绝 ..、绝对路径越界、符号链接逃逸等所有 regex 黑名单漏掉的攻击。
    """
    resolved = Path(target).expanduser().resolve()
    for r in allowed_roots:
        r_resolved = r.resolve()
        if resolved == r_resolved or resolved.is_relative_to(r_resolved):
            return resolved
    raise PathContainmentViolation(
        f"Path {resolved} outside allowed roots: "
        f"{[str(r.resolve()) for r in allowed_roots]}"
    )


# ============================================================================
# 6. Shield 网关装饰器 — Tier 0 四道确定性关卡
# ============================================================================

def _bind_args(func: Callable, args: tuple, kwargs: dict) -> dict:
    """用 inspect.signature 绑定全量参数（修复位置参数绕过 #1）。

    将位置参数也展开为 dict，让 Pydantic schema 能完整校验。
    """
    sig = inspect.signature(func)
    try:
        bound = sig.bind(*args, **kwargs)
    except TypeError as e:
        raise ValidationViolation(f"Argument binding failed: {e}") from e
    bound.apply_defaults()
    return dict(bound.arguments)


def parallax_shield(
    max_session_label: TrustLabel = TrustLabel.RESTRICTED,
    op_class: OpClass = OpClass.READ,
    schema: Optional[Type[BaseModel]] = None,
    path_field: Optional[str] = None,
    allowed_roots: Optional[List[Path]] = None,
    chronicle: Optional[Chronicle] = None,
):
    """Parallax Shield 网关装饰器——Tier 0 确定性防御。"""
    
    def _run_pre_checks(func, args, kwargs):
        session = get_session()
        chron = chronicle or get_chronicle()
        roots = allowed_roots if allowed_roots is not None else [Path.cwd()]

        logger.info(
            "--- [Shield] %s | op=%s | max=%s | session=%s ---",
            func.__name__, op_class.value,
            max_session_label.name, session.label.name,
        )

        # --- Tier 0a: Adversarial Validation ---
        if schema is not None:
            bound = _bind_args(func, args, kwargs)
            try:
                validated = schema(**bound)
                logger.info("[Shield] schema OK: %s", validated)
            except ValidationError as e:
                logger.error("[Shield] schema FAIL: %s", e)
                raise ValidationViolation(f"Intent violates schema: {e}") from e

        # --- Tier 0b: Path Containment ---
        target_path: Optional[Path] = None
        if path_field is not None:
            if path_field not in kwargs:
                raise PathContainmentViolation(f"path_field '{path_field}' not in kwargs")
            target_path = check_path_containment(kwargs[path_field], roots)
            kwargs[path_field] = str(target_path)

        # --- Tier 0c: IFC Lattice Check ---
        if not session.can_execute(max_session_label):
            logger.error("[Shield] IFC DENY: session=%s > max=%s", session.label.name, max_session_label.name)
            raise IFCViolation(
                f"Information Flow Control Violation: session tainted to "
                f"{session.label.name}, but '{func.__name__}' requires "
                f"<= {max_session_label.name}. Possible indirect prompt injection."
                f" Taint history: {session.taint_history}"
            )

        # --- Tier 0d: Chronicle CoW / 软删除降级 ---
        snapshot_path: Optional[Path] = None
        downgrade_result = None
        
        if op_class == OpClass.WRITE_DESTRUCTIVE and target_path is not None:
            logger.info("[Shield] destructive op downgraded: rm -> mv trash")
            dest = chron.soft_delete(target_path)
            downgrade_result = {"soft_deleted": str(dest), "original": str(target_path)}
        elif op_class == OpClass.WRITE_REVERSIBLE and target_path is not None:
            snapshot_path = chron.snapshot(target_path)
            
        if op_class == OpClass.SIDE_EFFECT_IRREVERSIBLE:
            if session.label > TrustLabel.PUBLIC:
                raise IFCViolation(f"Irreversible side-effect requires PUBLIC session, got {session.label.name}")
                
        return target_path, snapshot_path, chron, downgrade_result, kwargs

    def _run_rollback(e, target_path, snapshot_path, chron):
        logger.error("[Shield] execution crashed: %s. Rollback engaged.", e)
        if snapshot_path is not None and target_path is not None:
            try:
                chron.restore(snapshot_path, target_path)
                logger.info("[Shield] rollback OK: %s -> %s", snapshot_path, target_path)
            except Exception as re:
                logger.error("[Shield] rollback FAILED: %s", re)
                raise RollbackFailure(f"Execution failed and rollback failed: {re}") from re

    def decorator(func: Callable):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                target_path, snapshot_path, chron, downgrade_result, kwargs = _run_pre_checks(func, args, kwargs)
                if downgrade_result: return downgrade_result
                logger.info("[Shield] authorizing execution (async)...")
                try:
                    result = await func(*args, **kwargs)
                    logger.info("[Shield] execution OK")
                    return result
                except Exception as e:
                    _run_rollback(e, target_path, snapshot_path, chron)
                    raise
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                target_path, snapshot_path, chron, downgrade_result, kwargs = _run_pre_checks(func, args, kwargs)
                if downgrade_result: return downgrade_result
                logger.info("[Shield] authorizing execution (sync)...")
                try:
                    result = func(*args, **kwargs)
                    logger.info("[Shield] execution OK")
                    return result
                except Exception as e:
                    _run_rollback(e, target_path, snapshot_path, chron)
                    raise
            return sync_wrapper

    return decorator
