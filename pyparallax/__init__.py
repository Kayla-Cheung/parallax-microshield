"""PyParallax — Tier 0 Shield 网关 for AI Agent 零信任执行"""

from .core import (
    # 信任格
    TrustLabel,
    OpClass,
    # 异常分类
    ParallaxSecurityException,
    ValidationViolation,
    PathContainmentViolation,
    IFCViolation,
    RollbackFailure,
    # 会话
    SessionContext,
    get_session,
    new_session,
    tainted_reader,
    # Chronicle
    Chronicle,
    get_chronicle,
    reset_chronicle,
    # Path 校验
    check_path_containment,
    # 网关装饰器
    parallax_shield,
)

__version__ = "0.2.0"

__all__ = [
    # 信任格
    "TrustLabel",
    "OpClass",
    # 异常
    "ParallaxSecurityException",
    "ValidationViolation",
    "PathContainmentViolation",
    "IFCViolation",
    "RollbackFailure",
    # 会话
    "SessionContext",
    "get_session",
    "new_session",
    "tainted_reader",
    # Chronicle
    "Chronicle",
    "get_chronicle",
    "reset_chronicle",
    # Path
    "check_path_containment",
    # 装饰器
    "parallax_shield",
    "__version__",
]
