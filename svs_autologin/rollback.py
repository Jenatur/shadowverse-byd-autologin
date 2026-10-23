"""可回滚栈(docs/constraints.md C3)。

参考实现的 handle_exit 是顺序硬编码的清理,任一步抛异常,后面全部不执行,
留下一台半回滚的机器 —— 比不回滚还糟(开发侧架构拆解 缺陷 4)。

这里的语义(tests/test_failure_modes.py defect 4/5 是契约):

* ``push(name, undo)`` 记录一步回滚;
* ``undo_all()`` **逆序**执行;某一步失败只记入返回的错误列表,
  绝不阻断其余步骤;已执行过的栈会被清空,重复调用是空操作;
* 作为上下文管理器使用时,正常退出与异常退出都回滚,异常照常向上传播。
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List, NamedTuple, Optional

log = logging.getLogger(__name__)

UndoFn = Callable[[], Any]


class _Step(NamedTuple):
    name: str
    undo: UndoFn


class RollbackStack:
    """「已做的事」栈:每做一步就 push 一个对应的撤销闭包。"""

    def __init__(self) -> None:
        self._steps: List[_Step] = []

    def __enter__(self) -> "RollbackStack":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        # 异常照样传播(返回 False);回滚在退出时无条件执行。
        self.undo_all()
        return False

    def push(self, name: str, undo: UndoFn) -> None:
        """登记一步回滚。name 会出现在失败信息里,请取可读的名字。"""
        self._steps.append(_Step(name, undo))

    def undo_all(self) -> List[Exception]:
        """逆序回滚全部步骤;返回失败列表(空列表 = 全部成功)。"""
        errors: List[Exception] = []
        steps, self._steps = self._steps, []  # 先清空:undo_all 幂等
        for name, undo in reversed(steps):
            try:
                undo()
            except Exception as exc:  # 单步失败不能阻断其余回滚
                wrapped = RuntimeError(f"rollback step {name!r} failed: {exc}")
                log.error("回滚失败:%s(%s)", name, exc)
                errors.append(wrapped)
        return errors

    def is_empty(self) -> bool:
        return not self._steps
