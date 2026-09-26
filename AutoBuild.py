#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MC 自动补丁构建脚本（GitHub Actions）

同时构建 正式版(stable, b=0) 和 测试版(beta, b=1)。

流程:
    1. 确保签名证书存在
    2. 读取本地 state.json（记录每个 channel 的 apk_version 和共用的 so_tag）
    3. 对每个 channel 获取 bbk 远程版本（b=0/1）
    4. 获取 so 最新 release（总是取最新）
    5. 任一 channel 的 APK 版本变化 或 so tag 变化 -> 该 channel 需要构建
    6. 下载 so 到 so_patch/<ABI>/（tag 变化时重下）
    7. 解析分享链接 -> 下载 APK（保留原始文件名）
    8. apktool 解包 -> 修改 MainActivity.smali -> 注入 so
    9. apktool b --aapt <private-aapt2> 重打包
   10. zipalign + apksigner 签名
   11. 输出到 dist/<channel>/原文件名_patch.apk，更新 state.json
"""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import unquote

import requests

# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
VERSION_API = "https://api.mcarc.top/last_version"
GET_LINK_API = "https://bbk.endyun.ltd/api/get_link"

WORK_DIR = Path("build_work")
DIST_DIR = Path("dist")
STATE_FILE = Path("state.json")

KEYSTORE = Path(os.environ.get("KEYSTORE_PATH", "release.keystore"))
KS_PASS = os.environ.get("KEYSTORE_PASSWORD", "android")
KEY_ALIAS = os.environ.get("KEY_ALIAS", "release")
KEY_PASS = os.environ.get("KEY_PASSWORD", "android")

SO_REPO = os.environ.get("SO_REPO", "").strip()
SO_RELEASE = os.environ.get("SO_RELEASE", "latest").strip() or "latest"
SO_TOKEN = os.environ.get("SO_TOKEN", "").strip()

SO_PATCH_DIR = Path(os.environ.get("SO_PATCH_DIR", "so_patch"))

HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36",
}

ABI_KEYWORDS = {
    "ARMv7": ["armv7", "armeabi-v7a", "v7a", "-v7.", "_v7."],
    "ARMv8": ["armv8", "arm64-v8a", "arm64", "aarch64", "v8a", "-v8.", "_v8."],
}

# MainActivity 的目标路径与注入代码
MAIN_ACTIVITY_REL = Path("com/mojang/minecraftpe/MainActivity.smali")

INJECT_CODE = [
    '    const-string v0, "mtbinloader2"',
    '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V',
]

# 同时构建的 channel
CHANNELS = [
    {"name": "stable", "b": "0", "label": "正式版"},
    {"name": "beta",   "b": "1", "label": "测试版"},
]


def log(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# 签名证书
# --------------------------------------------------------------------------- #
def _generate_keystore() -> None:
    log("[!] 未找到 keystore，自动生成一个新的")
    subprocess.run(
        [
            "keytool", "-genkeypair", "-v",
            "-keystore", str(KEYSTORE),
            "-alias", KEY_ALIAS,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-storetype", "PKCS12",
            "-storepass", KS_PASS,
            "-keypass", KEY_PASS,
            "-dname", "CN=mc-build, OU=dev, O=dev, L=City, ST=State, C=CN",
        ],
        check=True,
    )
    log(f"[√] 已生成 {KEYSTORE} (alias={KEY_ALIAS})")


def _upload_secret_gh(name: str, value: str) -> bool:
    """Upload a GitHub Actions secret without ever printing its value."""
    if not shutil.which("gh"):
        log("[!] 未找到 gh CLI，无法自动上传 Secret")
        return False

    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    pat = os.environ.get("GH_PAT", "").strip()
    if not repo or not pat:
        log("[!] 缺少 GITHUB_REPOSITORY 或 GH_PAT")
        return False

    try:
        subprocess.run(
            ["gh", "secret", "set", name, "-R", repo, "-b", value],
            env={**os.environ, "GH_TOKEN": pat},
            check=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] 上传 Secret 失败: {e}")
        return False


def ensure_keystore() -> None:
    if KEYSTORE.exists():
        log(f"[*] 使用已有 keystore: {KEYSTORE}")
        return

    b64 = os.environ.get("KEYSTORE_B64", "").strip()
    if b64:
        log("[*] 从环境变量 KEYSTORE_B64 解码 keystore")
        tmp = KEYSTORE.with_suffix(KEYSTORE.suffix + ".tmp")
        try:
            raw = base64.b64decode(b64, validate=True)
            if not raw:
                raise ValueError("内容为空")
            tmp.write_bytes(raw)
            tmp.replace(KEYSTORE)
        except Exception as e:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            raise RuntimeError(f"KEYSTORE_B64 解码失败: {e}") from e
        log(f"[√] keystore 已恢复: {KEYSTORE}")
        return

    _generate_keystore()
    b64 = base64.b64encode(KEYSTORE.read_bytes()).decode("ascii")
    log("[*] 尝试把 keystore 上传到 GitHub Secret KEYSTORE_B64 ...")
    if _upload_secret_gh("KEYSTORE_B64", b64):
        log("[√] 已上传到 Secret KEYSTORE_B64")
    else:
        # Never print the private keystore material into CI logs.
        log("[!] 自动上传 KEYSTORE_B64 失败；请通过 GitHub Secret 安全保存该 keystore。")


# --------------------------------------------------------------------------- #
# 状态文件
# --------------------------------------------------------------------------- #
def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# APK 版本信息（bbk）
# --------------------------------------------------------------------------- #
def fetch_version_info(b_value: str) -> dict:
    log(f"[*] 请求 APK 版本接口 (b={b_value}): {VERSION_API}")
    r = requests.post(
        VERSION_API,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"b": b_value},
        timeout=60,
    )
    r.raise_for_status()
    data = r.json()
    log(f"[*] 接口返回: {json.dumps(data, ensure_ascii=False)[:400]}")
    return data


def parse_version_info(data) -> dict:
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]

    if isinstance(data, dict) and isinstance(data.get("message"), list) and data["message"]:
        item = data["message"][0]
    elif isinstance(data, list) and data:
        item = data[0]
    elif isinstance(data, dict):
        item = data
    else:
        raise ValueError(f"无法解析版本信息: {data!r}")

    version = item.get("version") or item.get("version_all") or item.get("ver")
    link_obj = item.get("link") or item.get("links") or {}
    onedrive = None
    for k, v in link_obj.items():
        if k.lower().replace(" ", "") == "onedrive" and isinstance(v, dict):
            onedrive = v
            break
    if onedrive is None:
        raise ValueError(f"未找到 OneDrive 链接: {link_obj!r}")

    links = {
        "ARMv7": onedrive.get("ARMv7") or onedrive.get("armv7"),
        "ARMv8": onedrive.get("ARMv8") or onedrive.get("armv8") or onedrive.get("ARM64"),
    }
    if not links["ARMv7"] and not links["ARMv8"]:
        raise ValueError(f"OneDrive 里没有 ARMv7/ARMv8 链接: {onedrive!r}")

    return {
        "version": version,
        "version_all": item.get("version_all"),
        "update_time": item.get("update_time"),
        "file_size": item.get("file_size"),
        "links": links,
    }


# --------------------------------------------------------------------------- #
# SO release
# --------------------------------------------------------------------------- #
def fetch_so_release_info() -> dict:
    if not SO_REPO:
        log("[!] 未配置 SO_REPO，跳过 so 检查")
        return {"tag": "", "assets": [], "matched": False}

    if SO_RELEASE == "latest":
        api = f"https://api.github.com/repos/{SO_REPO}/releases/latest"
    else:
        api = f"https://api.github.com/repos/{SO_REPO}/releases/tags/{SO_RELEASE}"

    headers = {"Accept": "application/vnd.github+json"}
    if SO_TOKEN:
        headers["Authorization"] = f"Bearer {SO_TOKEN}"

    log(f"[*] 请求 so release: {api}")
    r = requests.get(api, headers=headers, timeout=30)
    r.raise_for_status()
    rel = r.json()

    tag = rel.get("tag_name", "")
    assets = [
        {"name": a["name"], "url": a["browser_download_url"], "size": a["size"]}
        for a in rel.get("assets", [])
    ]
    log(f"[*] so release tag: {tag}，共 {len(assets)} 个 asset")
    return {"tag": tag, "assets": assets, "matched": True}


def _load_so_map() -> dict:
    p = Path("so_map.json")
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def download_so_assets(assets: list, dest_root: Path) -> int:
    if not assets:
        return 0
    so_map = _load_so_map()
    headers = {"User-Agent": "Mozilla/5.0"}
    if SO_TOKEN:
        headers["Authorization"] = f"Bearer {SO_TOKEN}"

    count = 0
    for a in assets:
        name = a["name"]
        if not name.lower().endswith(".so"):
            log(f"[so] 跳过非 .so 文件: {name}")
            continue
        low = name.lower()
        abi = next(
            (k for k, kws in ABI_KEYWORDS.items() if any(kw in low for kw in kws)),
            "_common",
        )
        mapped = so_map.get(abi, {}).get(name)
        rel = mapped if mapped else name
        dest = dest_root / abi / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        log(f"[so] 下载 {name} ({a['size']/1024/1024:.2f} MB) -> {dest.relative_to(dest_root)}")
        with requests.get(a["url"], headers=headers, stream=True, timeout=600) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for buf in r.iter_content(chunk_size=1 << 20):
                    if buf:
                        f.write(buf)
        count += 1
    log(f"[so] 共下载 {count} 个 .so 文件")
    return count


# --------------------------------------------------------------------------- #
# 解析 APK 下载直链
# --------------------------------------------------------------------------- #
def resolve_share_code(share_url: str) -> str:
    return share_url.rstrip("/").rsplit("/s/", 1)[-1]


def get_openlist_url(share_code: str) -> str:
    log(f"[*] 解析分享码: {share_code}")
    r = requests.post(
        GET_LINK_API,
        json={"s_link": share_code},
        headers={
            **HTTP_HEADERS,
            "Referer": "https://bbk.endyun.ltd/",
            "Origin": "https://bbk.endyun.ltd",
        },
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("status") != 200:
        raise RuntimeError(f"get_link 失败: {data}")
    msg = data.get("message") or []
    if not msg:
        raise RuntimeError(f"无效链接: {data}")
    o_link = msg[0]["o_link"]
    log(f"[*] openlist url: {o_link}")
    return o_link


def resolve_download_url(share_url: str) -> str:
    return get_openlist_url(resolve_share_code(share_url))


# --------------------------------------------------------------------------- #
# 流式下载
# --------------------------------------------------------------------------- #
def _safe_filename(name: str, fallback: str) -> str:
    name = name.strip().replace("\\", "/")
    name = Path(name).name
    if not name or name in {".", ".."}:
        return fallback
    # Avoid control characters and characters that are awkward in CI artifacts.
    name = re.sub(r"[\x00-\x1f\x7f]", "_", name)
    return name


def download_file(
    url: str,
    dest: Path,
    chunk: int = 1 << 20,
    validate_zip: bool = False,
) -> str:
    log(f"[*] 下载: {url[:120]}...")
    part = dest.with_name(dest.name + ".part")
    orig_name = dest.name

    try:
        with requests.get(url, headers=HTTP_HEADERS, stream=True, timeout=600) as r:
            r.raise_for_status()

            cd = r.headers.get("content-disposition", "")
            m = re.search(r"filename\*=UTF-8''([^;]+)", cd, re.I)
            if m:
                orig_name = unquote(m.group(1).strip().strip('"'))
            else:
                m = re.search(r'filename\s*=\s*"([^"]+)"', cd, re.I)
                if not m:
                    m = re.search(r"filename\s*=\s*([^;]+)", cd, re.I)
                if m:
                    orig_name = unquote(m.group(1).strip().strip('"'))

            orig_name = _safe_filename(orig_name, dest.name)
            if orig_name != dest.name:
                log(f"[*] 服务端文件名: {orig_name}")

            total = int(r.headers.get("content-length", 0) or 0)
            log(f"[*] 文件大小: {total/1024/1024:.2f} MB" if total else "[*] 文件大小未知")

            done = 0
            part.parent.mkdir(parents=True, exist_ok=True)
            with open(part, "wb") as f:
                for buf in r.iter_content(chunk_size=chunk):
                    if not buf:
                        continue
                    f.write(buf)
                    done += len(buf)
                    if total and done % (100 << 20) < chunk:
                        pct = done * 100 // total
                        log(f"    进度: {pct}% ({done/1024/1024:.1f}/{total/1024/1024:.1f} MB)")

            if total and done != total:
                raise RuntimeError(f"下载大小不一致: HTTP={total} 实际={done}")

        if validate_zip and not zipfile.is_zipfile(part):
            raise RuntimeError(f"下载文件不是有效 ZIP/APK: {part}")

        part.replace(dest)
        log(f"[*] 下载完成，共 {dest.stat().st_size/1024/1024:.2f} MB")
        return orig_name
    except Exception:
        try:
            part.unlink(missing_ok=True)
        except Exception:
            pass
        raise


# --------------------------------------------------------------------------- #
# apktool
# --------------------------------------------------------------------------- #
def _check_apktool() -> None:
    if not shutil.which("apktool"):
        raise RuntimeError("找不到 apktool")
    try:
        out = subprocess.check_output(["apktool", "--version"], text=True).strip()
        log(f"[*] apktool 版本: {out}")
    except Exception:
        pass


def _prepare_aapt2() -> str:
    """Return a verified, executable aapt2 path for Apktool.

    Priority:
      1. AAPT2_PATH supplied by GitHub Actions/workflow.
      2. aapt2 found on PATH.
      3. Android SDK build-tools.

    IMPORTANT:
      - Never chmod the Android SDK's original aapt2.
      - --aapt and --use-aapt2 must never be used together.
      - When the selected binary is not already a writable executable copy,
        copy it into WORK_DIR/_tools/aapt2 and chmod only that copy.
    """

    configured = os.environ.get("AAPT2_PATH", "").strip()
    source_path: Path | None = None

    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        candidate = candidate.resolve()
        if not candidate.is_file():
            raise RuntimeError(f"AAPT2_PATH 指向的文件不存在: {candidate}")
        source_path = candidate
        log(f"[*] 使用环境变量 AAPT2_PATH: {source_path}")

    if source_path is None:
        path_aapt2 = shutil.which("aapt2")
        if path_aapt2:
            source_path = Path(path_aapt2).resolve()
            log(f"[*] PATH 中找到 aapt2: {source_path}")

    if source_path is None:
        for env_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
            sdk = os.environ.get(env_name, "").strip()
            if not sdk:
                continue

            sdk_path = Path(sdk)
            if not sdk_path.is_dir():
                continue

            candidates = [
                p for p in sdk_path.glob("build-tools/*/aapt2")
                if p.is_file()
            ]
            if candidates:
                candidates.sort(key=lambda p: p.parent.name, reverse=True)
                source_path = candidates[0].resolve()
                log(f"[*] Android SDK 中找到 aapt2: {source_path}")
                break

    if source_path is None:
        raise RuntimeError(
            "找不到 aapt2，请安装 Android SDK Build Tools 或设置 AAPT2_PATH"
        )

    if not os.access(source_path, os.R_OK):
        raise RuntimeError(f"aapt2 无法读取: {source_path}")

    # 如果 workflow 已经提供一个工作区中的可执行副本，直接使用。
    try:
        source_is_workspace_copy = source_path.parent.resolve() == (WORK_DIR / "_tools").resolve()
    except OSError:
        source_is_workspace_copy = False

    if source_is_workspace_copy and os.access(source_path, os.X_OK):
        local_aapt2 = source_path
    else:
        local_dir = WORK_DIR / "_tools"
        local_dir.mkdir(parents=True, exist_ok=True)
        local_aapt2 = local_dir / "aapt2"

        # 只复制，不碰 Android SDK 原始文件的权限。
        shutil.copyfile(source_path, local_aapt2)
        os.chmod(local_aapt2, 0o755)

    if not local_aapt2.is_file():
        raise RuntimeError(f"aapt2 副本不存在: {local_aapt2}")

    if not os.access(local_aapt2, os.X_OK):
        raise RuntimeError(f"aapt2 不可执行: {local_aapt2}")

    try:
        result = subprocess.run(
            [str(local_aapt2), "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=True,
        )
    except Exception as e:
        raise RuntimeError(
            f"aapt2 无法正常执行: {local_aapt2}: {e}"
        ) from e

    version = next(
        (line.strip() for line in result.stdout.splitlines() if line.strip()),
        "unknown",
    )
    log(f"[*] 最终使用 aapt2: {local_aapt2}")
    log(f"[*] aapt2 版本: {version}")
    return str(local_aapt2)


def extract_with_apktool(apk: Path, out_dir: Path) -> None:
    log(f"[*] apktool 解包 -> {out_dir}")
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["apktool", "d", "-f", "-o", str(out_dir), str(apk)],
        check=True,
    )


def repack_with_apktool(src_dir: Path, out_apk: Path) -> None:
    """Build with Apktool using a private aapt2 copy.

    IMPORTANT: --aapt and --use-aapt2 are mutually exclusive in Apktool 2.11.x.
    """
    log(f"[*] apktool 打包 -> {out_apk}")
    if out_apk.exists():
        out_apk.unlink()

    aapt2 = _prepare_aapt2()
    cmd = [
        "apktool",
        "b",
        "--aapt", aapt2,
        str(src_dir),
        "-o", str(out_apk),
    ]
    log(f"[*] 执行: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    if not out_apk.is_file() or out_apk.stat().st_size == 0:
        raise RuntimeError(f"apktool 未生成有效 APK: {out_apk}")
    if not zipfile.is_zipfile(out_apk):
        raise RuntimeError(f"apktool 生成的文件不是有效 APK/ZIP: {out_apk}")


# --------------------------------------------------------------------------- #
# 修改 MainActivity.smali
# --------------------------------------------------------------------------- #
def find_main_activity(unpack_dir: Path) -> Path | None:
    for smali_dir in sorted(unpack_dir.glob("smali*")):
        candidate = smali_dir / MAIN_ACTIVITY_REL
        if candidate.is_file():
            return candidate
    return None


def _parameter_register_count(method_line: str) -> int:
    """Return Dalvik register width used by method parameters, including this."""
    if not method_line.startswith(".method"):
        raise ValueError(f"不是 method 声明: {method_line}")

    descriptor_match = re.search(r"\((.*?)\)[VZBSCIJFDL\[;]", method_line)
    if not descriptor_match:
        # Fallback for unusual/obfuscated declarations; this is deliberately
        # conservative because a wrong parameter count makes .registers unsafe.
        raise ValueError(f"无法解析方法参数: {method_line}")

    params = descriptor_match.group(1)
    count = 0
    i = 0
    while i < len(params):
        c = params[i]
        if c in "ZBSCIJFD":
            count += 2 if c in "JD" else 1
            i += 1
        elif c == "L":
            j = params.find(";", i)
            if j < 0:
                raise ValueError(f"非法对象参数描述符: {method_line}")
            count += 1
            i = j + 1
        elif c == "[":
            i += 1
            while i < len(params) and params[i] == "[":
                i += 1
            if i >= len(params):
                raise ValueError(f"非法数组参数描述符: {method_line}")
            if params[i] == "L":
                j = params.find(";", i)
                if j < 0:
                    raise ValueError(f"非法数组对象参数描述符: {method_line}")
                i = j + 1
            else:
                i += 1
            count += 1
        else:
            raise ValueError(f"未知参数描述符 {c!r}: {method_line}")

    # Non-static instance methods have the implicit 'this' parameter.
    if not re.search(r"\.method\s+.*\bstatic\b", method_line):
        count += 1
    return count


def patch_main_activity(smali_path: Path) -> bool:
    log(f"[*] 修改 smali: {smali_path}")
    text = smali_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    # Do not inject twice when rebuilding an already-patched APK.
    if 'System;->loadLibrary(Ljava/lang/String;)V' in text and '"mtbinloader2"' in text:
        log('[=] 已存在 System.loadLibrary("mtbinloader2")，跳过重复注入')
        return True

    out: list[str] = []
    in_target = False
    handled = False
    current_method_line = ""

    for line in lines:
        stripped = line.strip()

        if not in_target and stripped.startswith(".method"):
            # Exact method name/signature; do not require 'public'.
            if re.search(r"\bonCreate\(Landroid/os/Bundle;\)V\b", stripped):
                in_target = True
                current_method_line = stripped
            out.append(line)
            continue

        if in_target and not handled:
            m = re.match(r"\.locals\s+(\d+)$", stripped)
            if m:
                n = int(m.group(1))
                temp_reg = f"v{n}"
                out.append(line.replace(f".locals {n}", f".locals {n + 1}", 1))
                out.append(f'    const-string {temp_reg}, "mtbinloader2"')
                out.append(
                    f"    invoke-static {{{temp_reg}}}, "
                    "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
                )
                handled = True
                log(f"[*] .locals {n} -> .locals {n + 1}，使用临时寄存器 {temp_reg}")
                continue

            m = re.match(r"\.registers\s+(\d+)$", stripped)
            if m:
                total = int(m.group(1))
                param_regs = _parameter_register_count(current_method_line)
                locals_count = total - param_regs
                if locals_count < 0:
                    raise RuntimeError(
                        f"非法寄存器布局: .registers {total}, 参数需要 {param_regs}: {smali_path}"
                    )
                temp_reg = f"v{locals_count}"
                out.append(line.replace(f".registers {total}", f".registers {total + 1}", 1))
                out.append(f'    const-string {temp_reg}, "mtbinloader2"')
                out.append(
                    f"    invoke-static {{{temp_reg}}}, "
                    "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
                )
                handled = True
                log(
                    f"[*] .registers {total} -> .registers {total + 1}，"
                    f"参数寄存器={param_regs}，使用临时寄存器 {temp_reg}"
                )
                continue

        out.append(line)

        if in_target and stripped == ".end method":
            in_target = False

    if not handled:
        if in_target:
            raise RuntimeError(f"找到 onCreate 但没有找到 .locals/.registers: {smali_path}")
        log("[!] 未找到目标 onCreate(Landroid/os/Bundle;)V")
        return False

    smali_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    log('[√] 已注入 System.loadLibrary("mtbinloader2")')
    return True


# --------------------------------------------------------------------------- #
# 注入 .so
# --------------------------------------------------------------------------- #
def _android_abi(abi: str) -> str:
    if abi == "ARMv7":
        return "armeabi-v7a"
    if abi == "ARMv8":
        return "arm64-v8a"
    raise ValueError(f"未知 ABI: {abi}")


def _default_so_name(name: str) -> str:
    """Normalize mtbinloader2 release asset names to the JNI loadLibrary name."""
    if name == "libmtbinloader2.so":
        return name
    if name.startswith("libmtbinloader2_") and name.endswith(".so"):
        return "libmtbinloader2.so"
    if name.startswith("libmtbinloader2-") and name.endswith(".so"):
        return "libmtbinloader2.so"
    return name


def _safe_relative_path(path_text: str) -> Path:
    rel = Path(path_text)
    if rel.is_absolute() or ".." in rel.parts:
        raise RuntimeError(f"非法相对路径: {path_text}")
    return rel


def inject_so_files(so_dir: Path, unpack_dir: Path, abi: str) -> int:
    if not so_dir.exists() or not so_dir.is_dir():
        log(f"[!] 未找到 so 注入目录: {so_dir}")
        return 0

    log(f"[*] 从 {so_dir} 注入 .so 文件 (ABI={abi})")
    so_map = _load_so_map()
    android_abi = _android_abi(abi)
    count = 0

    for src in sorted(so_dir.rglob("*.so")):
        name = src.name
        mapped = so_map.get(abi, {}).get(name)

        if mapped:
            rel = _safe_relative_path(mapped)
            # A mapping that is only a filename still goes under the Android ABI dir.
            if len(rel.parts) == 1:
                rel = Path("lib") / android_abi / rel
        else:
            rel = Path("lib") / android_abi / _default_so_name(name)

        dst = unpack_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        count += 1
        log(f"[so] 注入 {src.name} -> {rel}")

    if count == 0:
        log(f"[!] {so_dir} 中没有可注入的 .so 文件")
    else:
        log(f"[so] 共注入 {count} 个文件")
    return count


# --------------------------------------------------------------------------- #
# zipalign + 签名
# --------------------------------------------------------------------------- #
def find_tool(name: str):
    p = shutil.which(name)
    if p:
        return p

    candidates: list[Path] = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        home = os.environ.get(env, "").strip()
        if not home:
            continue
        build_tools = Path(home) / "build-tools"
        if not build_tools.is_dir():
            continue
        candidates.extend(
            p for p in build_tools.glob(f"*/{name}")
            if p.is_file()
        )

    if candidates:
        candidates.sort(key=lambda p: p.parent.name, reverse=True)
        return str(candidates[0])

    return None


def zipalign_apk(src: Path, dst: Path) -> None:
    tool = find_tool("zipalign")
    if not tool:
        raise RuntimeError("找不到 zipalign")
    if dst.exists():
        dst.unlink()
    log(f"[*] zipalign: {tool}")
    subprocess.run([tool, "-f", "-p", "4", str(src), str(dst)], check=True)
    if not dst.is_file():
        raise RuntimeError(f"zipalign 没有生成文件: {dst}")


def sign_apk(src: Path, dst: Path) -> None:
    if not KEYSTORE.exists():
        raise FileNotFoundError(f"找不到签名证书: {KEYSTORE}")

    apksigner = find_tool("apksigner")
    if not apksigner:
        raise RuntimeError("找不到 apksigner，拒绝回退 jarsigner（无法保证 APK v2 签名）")

    if dst.exists():
        dst.unlink()

    log(f"[*] 使用 apksigner 签名 (v1 + v2): {apksigner}")
    subprocess.run(
        [
            apksigner, "sign",
            "--ks", str(KEYSTORE),
            "--ks-pass", f"pass:{KS_PASS}",
            "--key-pass", f"pass:{KEY_PASS}",
            "--ks-key-alias", KEY_ALIAS,
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--out", str(dst),
            str(src),
        ],
        check=True,
    )

    verify = subprocess.run(
        [apksigner, "verify", "--verbose", str(dst)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    log("[*] apksigner verify:")
    for line in verify.stdout.splitlines():
        log(f"    {line}")

    if verify.returncode != 0:
        raise RuntimeError(f"apksigner verify 失败: {dst}")

    verify_text = verify.stdout
    v2_match = re.search(
        r"Verified using v2 scheme .*?:\s*(true|false)",
        verify_text,
        re.I,
    )
    if v2_match and v2_match.group(1).lower() != "true":
        raise RuntimeError(f"APK 未通过 v2 签名验证: {dst}")

    if not dst.is_file() or dst.stat().st_size == 0:
        raise RuntimeError(f"签名后 APK 无效: {dst}")


# --------------------------------------------------------------------------- #
# 单架构构建
# --------------------------------------------------------------------------- #
def build_one(
    abi: str,
    share_url: str,
    version: str,
    channel: str,
    out_dir: Path,
) -> Path:
    log("=" * 60)
    log(f"[*] 构建 channel={channel} abi={abi} version={version}")

    abi_work = WORK_DIR / channel / abi
    if abi_work.exists():
        shutil.rmtree(abi_work)
    abi_work.mkdir(parents=True, exist_ok=True)

    # 1. 解析真实直链
    real_url = resolve_download_url(share_url)

    # 2. 下载 APK
    original_apk = abi_work / "original.apk"
    orig_name = download_file(real_url, original_apk, validate_zip=True)

    stem = Path(orig_name).stem
    if stem.lower().endswith("_patch"):
        out_name = f"{stem}.apk"
    else:
        out_name = f"{stem}_patch.apk"
    log(f"[*] 输出文件名: {out_name}")

    # 3. apktool 解包
    unpack_dir = abi_work / "unpack"
    extract_with_apktool(original_apk, unpack_dir)

    # 4. 修改 MainActivity.smali；失败直接停止，禁止生成假成功 APK
    main_activity = find_main_activity(unpack_dir)
    if not main_activity:
        raise RuntimeError(f"未找到 {MAIN_ACTIVITY_REL}")
    if not patch_main_activity(main_activity):
        raise RuntimeError(f"MainActivity patch 失败: {main_activity}")

    # 5. 注入正确 Android ABI 路径和库名
    abi_so_dir = SO_PATCH_DIR / abi
    if abi_so_dir.exists():
        injected = inject_so_files(abi_so_dir, unpack_dir, abi)
    else:
        injected = inject_so_files(SO_PATCH_DIR, unpack_dir, abi)

    if injected <= 0:
        raise RuntimeError(f"没有注入任何 .so: {abi}")

    # 6. apktool 打包 (唯一使用 --aapt，不再与 --use-aapt2 冲突)
    rebuilt_apk = abi_work / "rebuilt.apk"
    repack_with_apktool(unpack_dir, rebuilt_apk)

    # 7. zipalign + 签名 + 验证
    aligned_apk = abi_work / "aligned.apk"
    zipalign_apk(rebuilt_apk, aligned_apk)

    out_dir.mkdir(parents=True, exist_ok=True)
    out_apk = out_dir / out_name
    sign_apk(aligned_apk, out_apk)

    size_mb = out_apk.stat().st_size / 1024 / 1024
    sha256 = hashlib.sha256()
    with open(out_apk, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha256.update(chunk)

    log(f"[√] {channel}/{abi} 构建完成: {out_apk}  ({size_mb:.2f} MB)")
    log(f"    SHA256: {sha256.hexdigest()}")
    return out_apk


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> int:
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    try:
        ensure_keystore()
    except (FileNotFoundError, RuntimeError) as e:
        log(f"[x] {e}")
        return 1

    try:
        _check_apktool()
    except RuntimeError as e:
        log(f"[x] {e}")
        return 1

    state = load_state()
    local_so = state.get("so_tag", "")
    local_apks = state.get("apk_versions", {})
    log(f"[*] 本地状态: so={local_so or '(空)'}  apk={local_apks}")

    # SO 最新 release
    try:
        so_info = fetch_so_release_info()
        remote_so = so_info["tag"]
        if SO_REPO and (not so_info.get("matched") or not so_info.get("assets")):
            raise RuntimeError("SO_REPO 已配置，但最新 release 没有可用 .so asset")
    except Exception as e:
        log(f"[!] 获取 so release 失败: {e}")
        if SO_REPO:
            return 1
        so_info = {"tag": "", "assets": [], "matched": False}
        remote_so = ""

    so_changed = (
        bool(remote_so)
        and remote_so != local_so
        and bool(so_info["assets"])
    )

    jobs = []
    had_version_error = False
    for ch in CHANNELS:
        try:
            info = fetch_version_info(ch["b"])
            parsed = parse_version_info(info)
        except Exception as e:
            log(f"[!] {ch['label']} 获取版本失败: {e}")
            had_version_error = True
            continue

        remote_apk = str(parsed.get("version_all") or parsed["version"])
        local_apk = local_apks.get(ch["name"], "")
        apk_changed = remote_apk != local_apk

        log(
            f"[*] {ch['label']}({ch['name']}): 远程={remote_apk} "
            f"本地={local_apk or '(空)'} "
            f"{'变化' if apk_changed else '未变'}"
        )

        if apk_changed or so_changed:
            jobs.append(
                {
                    "channel": ch,
                    "remote_apk": remote_apk,
                    "links": parsed["links"],
                }
            )

    log(
        f"[*] SO: 远程={remote_so or '(无)'} 本地={local_so or '(空)'} "
        f"{'变化' if so_changed else '未变'}"
    )

    if not jobs:
        if had_version_error:
            log("[x] 存在版本接口错误，不返回成功")
            return 1
        log("[=] 所有 channel 均无更新，退出")
        return 0

    # 处理 so_patch（共用）
    if so_info["assets"] and (so_changed or not SO_PATCH_DIR.exists()):
        if SO_PATCH_DIR.exists():
            shutil.rmtree(SO_PATCH_DIR)
        SO_PATCH_DIR.mkdir(parents=True, exist_ok=True)
        count = download_so_assets(so_info["assets"], SO_PATCH_DIR)
        if count <= 0:
            log("[x] release 没有下载到任何 .so")
            return 1
    elif SO_PATCH_DIR.exists():
        log(f"[*] 复用现有 so_patch（tag={remote_so or local_so or '(local)'}）")
    else:
        log("[x] 没有可用 so_patch")
        return 1

    # 工作目录
    if WORK_DIR.exists():
        shutil.rmtree(WORK_DIR)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    results: dict[str, list[Path]] = {}
    all_ok = not had_version_error

    for job in jobs:
        ch = job["channel"]
        results[ch["name"]] = []
        for abi, url in (
            ("ARMv7", job["links"].get("ARMv7")),
            ("ARMv8", job["links"].get("ARMv8")),
        ):
            if not url:
                log(f"[!] 跳过 {ch['name']}/{abi}: 无下载链接")
                all_ok = False
                continue
            try:
                out = build_one(
                    abi=abi,
                    share_url=url,
                    version=job["remote_apk"],
                    channel=ch["name"],
                    out_dir=DIST_DIR / ch["name"],
                )
                results[ch["name"]].append(out)
            except Exception as e:
                log(f"[x] {ch['name']}/{abi} 构建失败: {e}")
                import traceback
                traceback.print_exc()
                all_ok = False

    if not any(results.values()):
        log("[x] 没有任何产物生成")
        return 1

    # 只有全部 requested jobs 成功才更新 state，避免跳过失败重试。
    if all_ok:
        new_apks = dict(local_apks)
        for job in jobs:
            new_apks[job["channel"]["name"]] = job["remote_apk"]
        save_state({"so_tag": remote_so, "apk_versions": new_apks})
        log(f"[*] 已记录状态: so={remote_so} apk={new_apks}")
    else:
        log("[!] 存在失败项，不记录状态，下次将重试")

    log("=" * 60)
    total = 0
    for ch_name, outs in results.items():
        if not outs:
            continue
        log(f"[√] channel={ch_name} 共 {len(outs)} 个产物:")
        for p in outs:
            log(f"    - {p}  ({p.stat().st_size/1024/1024:.2f} MB)")
            total += 1
    log(f"[√] 全部完成，共 {total} 个产物")
    log("=" * 60)

    # Outputs for GitHub Actions
    gho = os.environ.get("GITHUB_OUTPUT")
    if gho:
        with open(gho, "a", encoding="utf-8") as f:
            for job in jobs:
                ch = job["channel"]
                outs = results.get(ch["name"], [])
                if not outs:
                    continue
                tag = f"v{job['remote_apk']}-{ch['name']}"
                f.write(f"release_tag_{ch['name']}={tag}\n")
                f.write(f"apk_paths_{ch['name']}<<EOF\n")
                for p in outs:
                    f.write(f"{p}\n")
                f.write("EOF\n")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
