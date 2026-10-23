r"""预生成 mitmproxy CA(阶段 5 T7:install.ps1 调用)。

确定性生成,不用「起一次代理再杀」:``CertStore.from_store`` 就是
mitmdump 首启时生成 CA 的那条路径,直接调它,产物形态逐字节同源
(mitmproxy-ca.pem 私钥 + mitmproxy-ca-cert.pem 证书 + mitmproxy-ca-cert.cer
+ mitmproxy-ca-cert.p12)。

用法(install.ps1 用 runtime python 调)::

    python.exe tools\gen_ca.py                      # confdir 来自 paths(SVS_DATA_DIR/.installed/仓库根)
    python.exe tools\gen_ca.py D:\some\certs-dir    # 显式目录(测试)

已存在任何 ca 文件时**不动**(幂等):install.ps1 可重复跑,修复安装
不会换掉用户机器上已信任的 CA。
"""

from __future__ import annotations

import sys
from pathlib import Path

from mitmproxy.certs import CertStore

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from svs_autologin import paths  # noqa: E402


def generate(confdir: Path) -> Path:
    """生成 CA 到 ``confdir``(已存在则原样返回证书路径,幂等)。"""
    cert = confdir / "mitmproxy-ca-cert.pem"
    key = confdir / "mitmproxy-ca.pem"
    if cert.exists() and key.exists():
        print(f"CA already present: {cert}")
        return cert
    confdir.mkdir(parents=True, exist_ok=True)
    store = CertStore.from_store(str(confdir), "mitmproxy", 2048)
    # from_store 落盘后返回的是内存对象;证书文件已就位。
    print(f"CA generated: {cert}")
    return cert


def main() -> int:
    if len(sys.argv) > 2:
        print("usage: python gen_ca.py [confdir]", file=sys.stderr)
        return 2
    confdir = Path(sys.argv[1]) if len(sys.argv) == 2 else paths.confdir()
    generate(confdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
