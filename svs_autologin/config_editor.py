"""config.local.json 的窄编辑(阶段 5)。

GUI 要改配置里的个别键(auto.ma68、games.ma68.startup_path),但
``config.save_app_config`` 会**剥掉 ``_`` 注释键**再写盘 —— 用户手写的
注释、安装器写的说明,一次保存就没了。所以这里做 raw JSON 往返:

    json.load → 改一个键 → json.dump(indent=2, ensure_ascii=False)

Python 3.7+ dict 保序,round-trip 不动其他键的顺序;``_comment`` 与
``log_key`` 原样保留(后者 PC 链路不用,但文件里有就必须保住 ——
在别的机器上它可能是用户手工带过来的)。

不做校验 —— 校验是 ``config.load_app_config(validate=True)`` 的职责,
加载时自然发生;编辑器只保证「不改没让它改的东西」。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

from svs_autologin.errors import AutoLoginError

PathLike = Union[str, Path]


def _load_raw(path: PathLike) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise AutoLoginError(
            f"config 文件不存在:{p}(应先由安装器或用户从 config.example.json 创建)"
        )
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AutoLoginError(f"config 不是合法 JSON:{p} - {exc}") from exc
    if not isinstance(raw, dict):
        raise AutoLoginError(f"config 顶层必须是 JSON 对象:{p}")
    return raw


def _save_raw(config: Dict[str, Any], path: PathLike) -> Path:
    p = Path(path)
    p.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return p


def edit_auto(path: PathLike, game_id: str, uuid: str) -> Path:
    """``auto.<game_id> = uuid``。``uuid=""`` = 该游戏关自动登录(记录模式
    切换不经过这里 —— 那是环境变量;这里是 GUI 账号列表的「选择即记忆」)。

    缺 ``auto`` 节就建一个;其他键原样。
    """
    config = _load_raw(path)
    auto = config.get("auto")
    if not isinstance(auto, dict):
        auto = {}
        config["auto"] = auto
    auto[game_id] = uuid
    return _save_raw(config, path)


def set_startup_path(path: PathLike, game_id: str, exe: Optional[str]) -> Path:
    """``games.<game_id>.startup_path = exe``(GUI 设置页的游戏路径)。

    ``exe=None``/空 = 删除该键(回到「未配置,不自动启动游戏」)。
    """
    config = _load_raw(path)
    games = config.get("games")
    if not isinstance(games, dict):
        games = {}
        config["games"] = games
    game = games.get(game_id)
    if not isinstance(game, dict):
        game = {}
        games[game_id] = game
    if exe:
        game["startup_path"] = exe
    else:
        game.pop("startup_path", None)
    return _save_raw(config, path)
