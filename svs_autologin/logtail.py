"""日志尾随:GUI 日志页的地基(阶段 5)。

从任意时刻起跟踪一个只增日志文件的「新内容」:记住上次读到的字节偏移,
每次 ``poll()`` 只返回偏移之后的新行;文件被轮转(变小/被删后重建)时
自动从头重开 —— RotatingFileHandler 的 rename 语义是 backup 文件改名、
主文件重建,尾随方看到的症状就是「长度突然小于偏移」。

刻意不 tail 目录里的 ``.1`` 备份:轮转瞬间丢几行旧日志对 GUI 无所谓,
为它做多文件时序对齐才是过度设计(红线 0)。

坏字节不致命:日志里可能有非 UTF-8 片段(mitmdump 的上游响应 dump),
``errors="replace"`` 换成 U+FFFD 显示,尾随不能因为一行坏数据断流。
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Union

PathLike = Union[str, Path]


class LogTail:
    """一个文件的增量读取器。线程模型:GUI 的 QTimer 单线程轮询,无需锁。"""

    def __init__(self, path: PathLike) -> None:
        self.path = Path(path)
        self._offset = 0
        self._started = False
        self._identity: Optional[tuple] = None  # (dev, ino, mtime_ns, size): 轮转指纹

    @staticmethod
    def _identity_of(st) -> tuple:
        """文件身份。``st_ino`` 是「删掉又建回同尺寸文件」最可靠的判据。

        Windows/NTFS 上 ``st_ino`` 是文件索引(删除后重建必然不同),比
        ``mtime_ns`` 稳:同一时钟刻度内删了重建、或文件系统 mtime 精度粗
        (FAT/网络盘)时,只靠 mtime 会漏判轮转,尾随器就停在一个已经不
        存在的偏移上,直到文件长过它。
        """
        return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)

    def poll(self) -> List[str]:
        """返回自上次调用以来的完整新行(不含行尾符)。

        尾部不完整行(还没等到 ``\n``)**不返回也不消费** —— 留在下次
        poll,写方 flush 完整行后自然读到。文件不存在/不可读 = 静默空列表
        (代理还没写过日志是常态,不是错误)。
        """
        try:
            st = self.path.stat()
        except OSError:
            return []

        identity = self._identity_of(st)
        if not self._started:
            # 首次 poll:只看新内容,不回放历史(日志页是「现场」不是档案;
            # 要看历史,诊断包里有完整文件)。
            self._offset = st.st_size
            self._identity = identity
            self._started = True
            return []

        rotated = (
            st.st_size < self._offset            # 变小 = 重建(RotatingFileHandler 语义)
            or (st.st_size == self._offset and identity != self._identity)
            # ↑ 同尺寸但指纹变了 = 换了文件(删除后重建同尺寸);
            #   有未消费字节(size > offset)时永远按追加处理 —— 那是
            #   正常写入,不是轮转。
        )
        if rotated and st.st_size > 0:
            self._offset = 0
        self._identity = identity

        if st.st_size == self._offset:
            return []

        try:
            with self.path.open("rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
        except OSError:
            return []

        # 读到的就是新的;不信 size(文件可能在我们 stat 与 read 之间
        # 又被轮转/截断,read() 到 EOF 为止,天然安全)。
        self._offset += len(chunk)
        text = chunk.decode("utf-8", errors="replace")
        lines = text.split("\n")
        # 尾部不完整行:回退偏移,下次再读(见 docstring)。
        if not text.endswith("\n"):
            tail = lines.pop()
            self._offset -= len(tail.encode("utf-8", errors="replace"))
            # U+FFFD 替换后字节数可能与原文件不一致:这个偏移修正只在
            # 「替换没有发生」时精确;发生了也只影响下一次 poll 的起点
            # 少几个字节 —— 尾随,不是审计,可接受。
        return [ln.rstrip("\r") for ln in lines if ln != ""]


def current_mitm_log(log_dir: PathLike) -> Optional[Path]:
    """``log/mitm-*.log`` 里最新的一份(每次代理生命周期一个文件)。

    没有则 None。GUI 用它决定 mitm 尾随器当前指向哪个文件;代理重启换
    新文件时,调用方比对路径变化即可切换尾随器。
    """
    root = Path(log_dir)
    try:
        candidates = sorted(root.glob("mitm-*.log"))
    except OSError:
        return None
    return candidates[-1] if candidates else None
