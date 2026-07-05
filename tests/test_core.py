"""
PyParallax Tier 0 网关测试 — 覆盖 P0 修复点。

每个测试对应原代码的一个具体缺陷修复：
  test_positional_args_validated     → 修复 #1 位置参数绕过
  test_reset_not_exposed             → 修复 #2 reset 公开自毁
  test_local_write_blocked_when_tainted → 修复 #3 LOCAL_WRITE 漏检
  test_clearance_actually_enforced   → 修复 #4 clearance 装饰性
  test_path_traversal_blocked        → 修复 #5 路径 regex 弱
  test_chronicle_cow_rollback        → 修复 #6 虚假回滚
  test_taint_is_monotonic            → 修复 #7/信任单调性
  test_exception_classification      → 修复 #12 异常不分类型
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest
from pydantic import BaseModel, Field

# 让测试能找到 pyparallax 包
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyparallax import (
    TrustLabel,
    OpClass,
    ParallaxSecurityException,
    ValidationViolation,
    PathContainmentViolation,
    IFCViolation,
    RollbackFailure,
    parallax_shield,
    new_session,
    get_session,
    tainted_reader,
    Chronicle,
    reset_chronicle,
)


@pytest.fixture(autouse=True)
def isolated_session_and_chronicle(tmp_path, monkeypatch):
    """每个测试用例独立 session + 临时 Chronicle 目录"""
    monkeypatch.setenv("PARALLAX_ROOT", str(tmp_path / ".parallax"))
    reset_chronicle()
    new_session()
    yield tmp_path
    reset_chronicle()
    new_session()


# ============================================================================
# 修复 #1: 位置参数绕过 — schema 必须校验全量参数
# ============================================================================

class _GreetIntent(BaseModel):
    name: str = Field(..., min_length=2)

def test_positional_args_validated(isolated_session_and_chronicle):
    """位置参数也必须被 Pydantic 校验，不能因为 kwargs 为空就放行"""

    @parallax_shield(schema=_GreetIntent)
    def greet(name: str):
        return f"hi {name}"

    # 合法位置参数应放行
    assert greet("alice") == "hi alice"

    # 非法位置参数（name 太短）必须被拦截
    with pytest.raises(ValidationViolation):
        greet("a")  # 位置参数，不是 kwargs


# ============================================================================
# 修复 #2: reset() 公开自毁 — 应该不存在公开 reset
# ============================================================================

def test_reset_not_exposed(isolated_session_and_chronicle):
    """SessionContext 不应有公开 reset 方法"""
    sess = get_session()
    assert not hasattr(sess, "reset"), (
        "SessionContext.reset 不应存在 — 这会让被污染 Agent 自洗白"
    )


# ============================================================================
# 修复 #3 + #4: LOCAL_WRITE 漏检 + clearance 装饰性 — 统一格偏序比较
# ============================================================================

def test_local_write_blocked_when_tainted(isolated_session_and_chronicle):
    """被污染会话不能执行任何要求干净会话的操作，无论 op_class"""
    new_session()

    @parallax_shield(
        max_session_label=TrustLabel.PUBLIC,
        op_class=OpClass.WRITE_REVERSIBLE,  # 之前的漏网之鱼
    )
    def write_local():
        return "ok"

    # 干净会话放行
    assert write_local() == "ok"

    # 被污染后必须熔断
    get_session().taint(TrustLabel.RESTRICTED, source="test")
    with pytest.raises(IFCViolation):
        write_local()


def test_clearance_actually_enforced(isolated_session_and_chronicle):
    """max_session_label 必须真正参与决策，而不只是 log"""
    new_session()

    @parallax_shield(max_session_label=TrustLabel.PUBLIC)
    def dangerous():
        return "executed"

    # 干净会话 OK
    assert dangerous() == "executed"

    # INTERNAL 级污染也应拦截 PUBLIC-only 操作
    get_session().taint(TrustLabel.INTERNAL, source="test")
    with pytest.raises(IFCViolation):
        dangerous()


# ============================================================================
# 修复 #5: 路径 regex 弱 — 改用 resolve + is_relative_to
# ============================================================================

class _TouchIntent(BaseModel):
    path: str

def test_path_traversal_blocked(isolated_session_and_chronicle, tmp_path):
    """.. 越界、绝对路径逃逸必须被拒绝"""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "inside.txt").write_text("ok")

    @parallax_shield(
        op_class=OpClass.READ,
        path_field="path",
        allowed_roots=[sandbox],
    )
    def read_file(path: str):
        return Path(path).read_text()

    # 沙箱内放行
    assert read_file(path=str(sandbox / "inside.txt")) == "ok"

    # .. 越界拒绝
    with pytest.raises(PathContainmentViolation):
        read_file(path=str(sandbox / ".." / ".." / "etc" / "passwd"))

    # 绝对路径逃逸拒绝
    with pytest.raises(PathContainmentViolation):
        read_file(path="/etc/passwd")


# ============================================================================
# 修复 #6: 虚假回滚 — Chronicle 真正实现 CoW 快照 + 回滚
# ============================================================================

def test_chronicle_cow_rollback(isolated_session_and_chronicle, tmp_path):
    """WRITE_REVERSIBLE 操作崩溃时，Chronicle 必须能从快照还原"""
    target = tmp_path / "important.txt"
    original_content = "ORIGINAL"
    target.write_text(original_content)

    chron = Chronicle()

    @parallax_shield(
        op_class=OpClass.WRITE_REVERSIBLE,
        path_field="path",
        allowed_roots=[tmp_path],
        chronicle=chron,
    )
    def crash_write(path: str):
        # 模拟覆写中途崩溃
        Path(path).write_text("CORRUPTED")
        raise RuntimeError("disk full")

    with pytest.raises(RuntimeError):
        crash_write(path=str(target))

    # 文件应被还原为原始内容
    assert target.read_text() == original_content, (
        "Chronicle 应在崩溃后从快照还原文件"
    )


def test_chronicle_soft_delete_replaces_rm(isolated_session_and_chronicle, tmp_path):
    """WRITE_DESTRUCTIVE 必须降级为 mv 到 trash，不调用原函数"""
    target = tmp_path / "victim.txt"
    target.write_text("data")

    chron = Chronicle()

    @parallax_shield(
        op_class=OpClass.WRITE_DESTRUCTIVE,
        path_field="path",
        allowed_roots=[tmp_path],
        chronicle=chron,
    )
    def rm_file(path: str):
        # 这个 raise 不应触发——原函数根本不应被调用
        raise AssertionError("destructive op should not call wrapped function")

    result = rm_file(path=str(target))
    assert "soft_deleted" in result
    assert not target.exists(), "原文件应已被 mv 移走"
    # trash 内应有该文件
    trashed = list(chron.trash.iterdir())
    assert len(trashed) == 1


# ============================================================================
# 信任单调性 — taint 只能升不能降
# ============================================================================

def test_taint_is_monotonic(isolated_session_and_chronicle):
    """taint 单调上升，无法降级"""
    sess = get_session()
    assert sess.label == TrustLabel.PUBLIC

    sess.taint(TrustLabel.CONFIDENTIAL, "leaked cred")
    assert sess.label == TrustLabel.CONFIDENTIAL

    # 试图降级到 INTERNAL — 当前 label 不变
    sess.taint(TrustLabel.INTERNAL, "try downgrade")
    assert sess.label == TrustLabel.CONFIDENTIAL, "taint 不能降级"

    # 升级到 RESTRICTED OK
    sess.taint(TrustLabel.RESTRICTED, "external data")
    assert sess.label == TrustLabel.RESTRICTED


def test_tainted_reader_does_not_restore(isolated_session_and_chronicle):
    """tainted_reader 退出后 taint 不还原——这是反绕过设计"""
    sess = get_session()
    assert sess.label == TrustLabel.PUBLIC

    with tainted_reader(TrustLabel.RESTRICTED, "external.pdf"):
        pass

    assert sess.label == TrustLabel.RESTRICTED, (
        "离开 with 块后 taint 必须保留，否则 Agent 可在 with 外绕过 IFC"
    )


# ============================================================================
# 修复 #12: 异常分类 — 不同失败原因应抛不同异常类型
# ============================================================================

def test_exception_classification(isolated_session_and_chronicle, tmp_path):
    """不同 Tier 失败应抛不同异常子类，便于调用方差异化处理"""
    new_session()

    class _StrictIntent(BaseModel):
        x: int = Field(..., ge=0)

    @parallax_shield(schema=_StrictIntent)
    def needs_positive(x: int):
        return x

    # Tier 0a: schema 失败 -> ValidationViolation
    with pytest.raises(ValidationViolation):
        needs_positive(x=-1)

    # Tier 0c: IFC 失败 -> IFCViolation（而非笼统的 ParallaxSecurityException）
    @parallax_shield(max_session_label=TrustLabel.PUBLIC)
    def dangerous():
        return "ok"

    get_session().taint(TrustLabel.RESTRICTED, "test")
    with pytest.raises(IFCViolation):
        dangerous()

    # 都是 ParallaxSecurityException 子类
    assert issubclass(ValidationViolation, ParallaxSecurityException)
    assert issubclass(IFCViolation, ParallaxSecurityException)
    assert issubclass(PathContainmentViolation, ParallaxSecurityException)
    assert issubclass(RollbackFailure, ParallaxSecurityException)


# ============================================================================
# 修复 #10: 线程/async 隔离 — contextvars 自然隔离
# ============================================================================

def test_new_session_isolates_taint(isolated_session_and_chronicle):
    """new_session() 必须重置 taint 状态，物理隔离新旧会话

    v0.2+ 隔离机制：SessionContext 是无状态 facade 单例，对象身份相同，
    但底层 label/history 存于 contextvars。new_session() 通过 set() 重置
    当前 context 的绑定，taint 不跟随。这是真正的"逻辑隔离"而非"物理对象隔离"。
    """
    s1 = get_session()
    s1.taint(TrustLabel.RESTRICTED, "old session")
    assert s1.label == TrustLabel.RESTRICTED

    # 开新会话——taint 必须不跟随
    s2 = new_session()
    assert s2.label == TrustLabel.PUBLIC
    assert s2.taint_history == []
    # facade 单例身份相同，但状态已隔离（通过 contextvars）
    assert s1 is s2  # 同一个 facade 对象
    assert s1.label == TrustLabel.PUBLIC  # 但 label 已重置
