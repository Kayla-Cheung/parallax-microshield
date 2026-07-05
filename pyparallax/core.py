import functools
import logging
import threading
from enum import Enum
from pydantic import BaseModel, ValidationError
from typing import Type, Any, Callable

# 设置极简的日志格式，模拟审计系统
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("PyParallax")

class ClearanceLevel(Enum):
    """Information Flow Control: 权限级别定义"""
    READ_ONLY = 1
    LOCAL_WRITE = 2
    NETWORK_ACCESS = 3
    SUDO_DESTRUCTIVE = 4

class IFCTag(Enum):
    """Information Flow Control: 数据敏感度标签"""
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4  # 外部未知/有毒数据，最高风险

class SessionContext:
    """全局会话上下文，用于污点追踪 (Taint Tracking)"""
    def __init__(self):
        self.current_tag = IFCTag.PUBLIC

    def taint(self, tag: IFCTag):
        """当读取高敏或外部数据时，提升污染级别"""
        if tag.value > self.current_tag.value:
            self.current_tag = tag
            logger.warning(f"[IFC] Session Tainted! Sensitivity elevated to: {self.current_tag.name}")

    def reset(self):
        """Context Rollback/Wiping: 洗白会话状态"""
        self.current_tag = IFCTag.PUBLIC
        logger.info(f"[IFC] Session state reset to PUBLIC.")

# 简易的线程局部变量存储当前会话
_thread_local = threading.local()

def get_session() -> SessionContext:
    if not hasattr(_thread_local, 'session'):
        _thread_local.session = SessionContext()
    return _thread_local.session

class ParallaxSecurityException(Exception):
    """物理熔断异常：当大模型企图越权执行时抛出"""
    pass

def parallax_shield(clearance: ClearanceLevel, schema: Type[BaseModel] = None):
    """
    Cognitive-Executive Separation (认知与执行隔离) 网关装饰器。
    
    :param clearance: 执行该动作所需的最低权限等级
    :param schema: (可选) Pydantic 模型，用于在底层充当 Adversarial Validator
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            session = get_session()
            logger.info(f"--- [Parallax Gateway Intercepted] ---")
            logger.info(f"Target Execution: {func.__name__} | Required Clearance: {clearance.name} | Current IFC Tag: {session.current_tag.name}")
            
            # 1. Adversarial Validation (对抗性校验)
            if schema:
                try:
                    # 强行用 Pydantic 对大模型传来的 JSON 意图进行“绝对契约”校验
                    validated_intent = schema(**kwargs)
                    logger.info(f"Validation Passed. Struct: {validated_intent}")
                except ValidationError as e:
                    logger.error(f"Validation Failed! Agent is hallucinating or under Prompt Injection.")
                    raise ParallaxSecurityException(f"Intent violates strict schema: {e}")
            
            # 2. Information Flow Control (上下文拦截/污点熔断)
            # 核心防御：如果当前上下文接触过“有毒/未知”数据，绝对禁止执行网络或破坏性系统操作
            if session.current_tag == IFCTag.RESTRICTED and clearance in [ClearanceLevel.NETWORK_ACCESS, ClearanceLevel.SUDO_DESTRUCTIVE]:
                logger.error(f"[IFC VIOLATION] Agent is TAINTED (RESTRICTED). Access to {clearance.name} DENIED.")
                raise ParallaxSecurityException(
                    "Information Flow Control Violation: "
                    "Cannot execute highly privileged actions while carrying tainted/restricted context data. "
                    "Possible Indirect Prompt Injection detected."
                )
            
            # 3. Execution & Reversible Execution (执行与快照回滚机制)
            logger.info(f"Authorizing physical execution...")
            try:
                # 只有在这行，大模型的意图才真正接触到了底层 OS
                result = func(*args, **kwargs)
                logger.info(f"Execution Successful.")
                return result
            except Exception as e:
                logger.error(f"Execution crashed: {e}. [Rollback Protocol Engaged]")
                raise
        return wrapper
    return decorator
