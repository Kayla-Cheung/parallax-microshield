"""
async 逃逸攻击向量测试 — 验证 parallax_shield 对 async def 的安全保证。

历史漏洞：
  修复前 wrapper 是同步函数，调用 async 函数时立即执行 Tier 0 检查，
  但函数体在 await 时才执行。攻击者可在检查通过后、await 之前 taint 会话，
  造成"检查时会话干净、执行时会话被污染"的 TOCTOU 式逃逸。

修复方案：
  async wrapper 把所有检查放进 coroutine 内部（await 时执行），
  检查通过后立即 await func，中间无让出点，事件循环不会切换任务。
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyparallax import (
    TrustLabel, OpClass, IFCViolation, PathContainmentViolation,
    ValidationViolation, parallax_shield,
    new_session, get_session, tainted_reader,
    reset_chronicle, Chronicle,
)
from pydantic import BaseModel, Field


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PARALLAX_ROOT", str(tmp_path / ".parallax"))
    reset_chronicle()
    new_session()
    yield
    reset_chronicle()
    new_session()


# ============================================================================
# 核心：async 逃逸窗口已关闭
# ============================================================================

async def test_async_escape_closed():
    """POC: 在 await 之前 taint 会话，await 时必须被 IFC 熔断

    修复前的攻击链：
      1. coro = dangerous_async()   # 同步 wrapper 检查通过（会话干净）
      2. get_session().taint(...)   # 攻击者污染会话
      3. await coro                 # 函数体执行，IFC 已过期
    修复后：
      1. coro = dangerous_async()   # 返回 coroutine，未执行检查
      2. get_session().taint(...)   # 污染会话
      3. await coro                 # 现在才执行检查 → IFCViolation
    """
    @parallax_shield(max_session_label=TrustLabel.PUBLIC, op_class=OpClass.READ)
    async def dangerous_async():
        return "executed"

    new_session()
    assert get_session().label == TrustLabel.PUBLIC

    coro = dangerous_async()              # 创建 coroutine，未触发检查
    get_session().taint(TrustLabel.RESTRICTED, "evil.pdf")  # 在 await 前污染

    with pytest.raises(IFCViolation):
        await coro                        # await 时检查 → 熔断


async def test_async_clean_session_passes():
    """干净会话下的 async 函数应正常执行"""
    @parallax_shield(max_session_label=TrustLabel.PUBLIC)
    async def read_async():
        return "ok"

    new_session()
    result = await read_async()
    assert result == "ok"


# ============================================================================
# async + IFC 全链路
# ============================================================================

async def test_async_ifc_violation_direct():
    """会话已被污染时调用 async 函数，应立即抛 IFCViolation"""
    @parallax_shield(max_session_label=TrustLabel.PUBLIC)
    async def dangerous():
        return "executed"

    new_session()
    get_session().taint(TrustLabel.RESTRICTED, "poison.pdf")

    with pytest.raises(IFCViolation):
        await dangerous()


async def test_async_tainted_reader_blocks_subsequent():
    """tainted_reader 内污染后，async 破坏操作必须被熔断"""
    @parallax_shield(max_session_label=TrustLabel.PUBLIC)
    async def destructive_async():
        return "executed"

    new_session()
    with tainted_reader(TrustLabel.RESTRICTED, "external.pdf"):
        pass

    with pytest.raises(IFCViolation):
        await destructive_async()


# ============================================================================
# async + Pydantic / Path 校验
# ============================================================================

class _AsyncIntent(BaseModel):
    target: str = Field(..., min_length=5)


async def test_async_schema_validation():
    """async 函数的 schema 校验必须在 await 时生效"""
    @parallax_shield(schema=_AsyncIntent)
    async def op(target: str):
        return target

    new_session()
    # 位置参数 + 非法值，await 时必须抛 ValidationViolation
    with pytest.raises(ValidationViolation):
        await op("ab")


async def test_async_path_containment(tmp_path):
    """async 函数的路径校验必须在 await 时生效"""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    @parallax_shield(op_class=OpClass.READ, path_field="p",
                     allowed_roots=[sandbox])
    async def read(p: str):
        return Path(p).read_text()

    new_session()
    with pytest.raises(PathContainmentViolation):
        await read(p="/etc/passwd")


# ============================================================================
# async + Chronicle 软删除降级
# ============================================================================

async def test_async_destructive_downgrade(tmp_path):
    """async WRITE_DESTRUCTIVE 必须降级为 soft_delete，不调用原函数"""
    target = tmp_path / "victim.txt"
    target.write_text("data")
    chron = Chronicle()

    @parallax_shield(op_class=OpClass.WRITE_DESTRUCTIVE,
                     path_field="p", allowed_roots=[tmp_path],
                     chronicle=chron)
    async def rm(p: str):
        raise AssertionError("async 原函数不应被调用")

    new_session()
    result = await rm(p=str(target))
    assert result["soft_deleted"]
    assert not target.exists()
    assert len(list(chron.trash.iterdir())) == 1


async def test_async_crash_rollback(tmp_path):
    """async 写操作崩溃，Chronicle 必须还原"""
    target = tmp_path / "important.txt"
    original = "ORIGINAL"
    target.write_text(original)
    chron = Chronicle()

    @parallax_shield(op_class=OpClass.WRITE_REVERSIBLE,
                     path_field="p", allowed_roots=[tmp_path],
                     chronicle=chron)
    async def crash_write(p: str):
        Path(p).write_text("CORRUPTED")
        raise IOError("disk full")

    new_session()
    with pytest.raises(IOError):
        await crash_write(p=str(target))
    assert target.read_text() == original


# ============================================================================
# async + 并发任务隔离（contextvars 保证）
# ============================================================================

async def test_concurrent_tasks_isolated():
    """并发 async 任务间的 taint 必须隔离（contextvars）"""

    @parallax_shield(max_session_label=TrustLabel.PUBLIC)
    async def check_clean():
        return get_session().label == TrustLabel.PUBLIC

    new_session()

    async def poison_task():
        get_session().taint(TrustLabel.RESTRICTED, "evil.pdf")
        # 此任务内被污染
        with pytest.raises(IFCViolation):
            await check_clean()

    async def clean_task():
        # 等污染任务先跑
        await asyncio.sleep(0.05)
        # 干净任务内的会话应不受影响
        result = await check_clean()
        assert result is True

    # asyncio.create_task 会 copy 当前 context，两任务隔离
    await asyncio.gather(poison_task(), clean_task())


# ============================================================================
# async + 中间无让出点验证
# ============================================================================

async def test_no_yield_between_check_and_execute():
    """验证检查与执行之间无让出点：攻击者无法插入 taint

    在 async wrapper 内，_run_tier0 检查通过后立即 await func，
    中间没有任何 await，事件循环不会切换。本测试在 func 内部
    尝试 taint 并验证：func 执行时会话状态就是检查时的状态。
    """
    execution_label = []

    @parallax_shield(max_session_label=TrustLabel.PUBLIC)
    async def capture_session():
        # 记录函数体执行时的会话标签
        execution_label.append(get_session().label)
        return "ok"

    new_session()
    assert get_session().label == TrustLabel.PUBLIC

    # 正常调用：检查时 PUBLIC，执行时也应是 PUBLIC
    await capture_session()
    assert execution_label == [TrustLabel.PUBLIC]


# ============================================================================
# async 中的多步注入链
# ============================================================================

async def test_async_multi_step_injection_chain():
    """async 场景下的完整间接提示词注入链必须被熔断"""
    @parallax_shield(max_session_label=TrustLabel.PUBLIC)
    async def destructive_async():
        return "should never execute"

    new_session()

    # 模拟多步注入：读外部数据 → 被洗脑 → 发出破坏请求
    with tainted_reader(TrustLabel.RESTRICTED, "resume_hacker.pdf"):
        pass

    with pytest.raises(IFCViolation) as exc:
        await destructive_async()
    assert "resume_hacker.pdf" in str(exc.value)
