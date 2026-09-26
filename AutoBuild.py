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
    9. apktool b --use-aapt2 重打包
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
        try:
            KEYSTORE.write_bytes(base64.b64decode(b64))
        except Exception as e:
            raise RuntimeError(f"KEYSTORE_B64 解码失败: {e}")
        return
    _generate_keystore()
    b64 = base64.b64encode(KEYSTORE.read_bytes()).decode()
    log("[*] 尝试把 keystore 上传到 GitHub Secret KEYSTORE_B64 ...")
    if _upload_secret_gh("KEYSTORE_B64", b64):
        log("[√] 已上传到 Secret KEYSTORE_B64")
    else:
        log("[!] 上传失败！请手动把下面的 base64 存到 Secret KEYSTORE_B64：")
        log("=" * 60)
        log(b64)
        log("=" * 60)


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
def download_file(url: str, dest: Path, chunk: int = 1 << 20) -> str:
    log(f"[*] 下载: {url[:120]}...")
    with requests.get(url, headers=HTTP_HEADERS, stream=True, timeout=600) as r:
        r.raise_for_status()
        orig_name = dest.name
        cd = r.headers.get("content-disposition", "")
        m = re.search(r"filename\*?=(?:UTF-8''|\"?)([^\";]+)", cd, re.I)
        if m:
            orig_name = unquote(m.group(1).strip().strip('"'))
            log(f"[*] 服务端文件名: {orig_name}")
        total = int(r.headers.get("content-length", 0))
        log(f"[*] 文件大小: {total/1024/1024:.2f} MB" if total else "[*] 文件大小未知")
        done = 0
        with open(dest, "wb") as f:
            for buf in r.iter_content(chunk_size=chunk):
                if not buf:
                    continue
                f.write(buf)
                done += len(buf)
                if total and done % (100 << 20) < chunk:
                    pct = done * 100 // total
                    log(f"    进度: {pct}% ({done/1024/1024:.1f}/{total/1024/1024:.1f} MB)")
    log(f"[*] 下载完成，共 {dest.stat().st_size/1024/1024:.2f} MB")
    return orig_name


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
    log(f"[*] apktool 打包 -> {out_apk}")
    if out_apk.exists():
        out_apk.unlink()
    aapt2 = os.environ.get("AAPT2", "").strip()
    cmd = ["apktool", "b"]
    if aapt2 and Path(aapt2).exists():
        log(f"[*] 使用系统 aapt2: {aapt2}")
        cmd += ["--aapt", aapt2]
    else:
        log("[!] 未找到 AAPT2 环境变量，使用 apktool 自带 aapt2")
    cmd += [str(src_dir), "-o", str(out_apk)]
    log(f"[*] 执行: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


# --------------------------------------------------------------------------- #
# 修改 MainActivity.smali
# --------------------------------------------------------------------------- #
def find_main_activity(unpack_dir: Path) -> Path | None:
    for smali_dir in sorted(unpack_dir.glob("smali*")):
        candidate = smali_dir / MAIN_ACTIVITY_REL
        if candidate.is_file():
            return candidate
    return None


def patch_main_activity(smali_path: Path) -> bool:
    log(f"[*] 修改 smali: {smali_path}")
    text = smali_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    out: list[str] = []
    in_oncreate = False
    handled = False

    for line in lines:
        stripped = line.strip()
        indent = line[: len(line) - len(line.lstrip())]

        if not in_oncreate and stripped.startswith(".method"):
            if "onCreate(" in stripped and "public" in stripped:
                in_oncreate = True
                out.append(line)
                continue

        if in_oncreate and not handled:
            m = re.match(r"\.locals\s+(\d+)", stripped)
            if m:
                n = int(m.group(1))
                new_regs = n + 4
                log(f"[*] .locals {n} -> .registers {new_regs}")
                out.append(f"{indent}.registers {new_regs}")
                out.extend(INJECT_CODE)
                handled = True
                continue

            m2 = re.match(r"\.registers\s+(\d+)", stripped)
            if m2:
                n = int(m2.group(1))
                if n < 6:
                    log(f"[*] .registers {n} -> .registers 6")
                    out.append(f"{indent}.registers 6")
                else:
                    out.append(line)
                out.extend(INJECT_CODE)
                handled = True
                continue

        out.append(line)

        if in_oncreate and stripped == ".end method":
            in_oncreate = False

    if handled:
        smali_path.write_text("\n".join(out) + "\n", encoding="utf-8")
        log('[√] 已注入 System.loadLibrary("mtbinloader2")')
    else:
        log("[!] 未在 MainActivity 的 onCreate 中找到 .locals / .registers")
    return handled


# --------------------------------------------------------------------------- #
# 注入 .so
# --------------------------------------------------------------------------- #
def inject_so_files(so_dir: Path, unpack_dir: Path) -> int:
    if not so_dir.exists() or not so_dir.is_dir():
        log(f"[!] 未找到 so 注入目录: {so_dir}，跳过 so 注入")
        return 0
    log(f"[*] 从 {so_dir} 注入 .so 文件")
    count = 0
    for src in sorted(so_dir.rglob("*.so")):
        rel = src.relative_to(so_dir)
        dst = unpack_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        count += 1
        log(f"[so] 注入 {rel}")
    log(f"[so] 共注入 {count} 个文件")
    return count


# --------------------------------------------------------------------------- #
# zipalign + 签名
# --------------------------------------------------------------------------- #
def find_tool(name: str):
    p = shutil.which(name)
    if p:
        return p
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        home = os.environ.get(env)
        if not home:
            continue
        base = Path(home)
        if not base.exists():
            continue
        for cand in base.rglob(name):
            if cand.is_file():
                return str(cand)
    return None


def zipalign_apk(src: Path, dst: Path) -> None:
    tool = find_tool("zipalign")
    if not tool:
        log("[!] 未找到 zipalign，跳过对齐")
        shutil.copy(src, dst)
        return
    log("[*] zipalign 对齐 (4 字节)")
    subprocess.run([tool, "-f", "-p", "4", str(src), str(dst)], check=True)


def sign_apk(src: Path, dst: Path) -> None:
    if not KEYSTORE.exists():
        raise FileNotFoundError(f"找不到签名证书: {KEYSTORE}")
    apksigner = find_tool("apksigner")
    if apksigner:
        log("[*] 使用 apksigner 签名 (v1 + v2)")
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
        return
    log("[!] 未找到 apksigner，回退到 jarsigner")
    shutil.copy(src, dst)
    subprocess.run(
        [
            "jarsigner", "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256",
            "-keystore", str(KEYSTORE),
            "-storepass", KS_PASS,
            "-keypass", KEY_PASS,
            str(dst), KEY_ALIAS,
        ],
        check=True,
    )


# --------------------------------------------------------------------------- #
# 单架构构建
# --------------------------------------------------------------------------- #
def build_one(abi: str, share_url: str, version: str,
              channel: str, out_dir: Path) -> Path:
    log("=" * 60)
    log(f"[*] 构建 channel={channel} abi={abi}")

    abi_work = WORK_DIR / channel / abi
    if abi_work.exists():
        shutil.rmtree(abi_work)
    abi_work.mkdir(parents=True, exist_ok=True)

    # 1. 解析真实直链
    real_url = resolve_download_url(share_url)

    # 2. 下载 APK
    original_apk = abi_work / "original.apk"
    orig_name = download_file(real_url, original_apk)

    stem = Path(orig_name).stem
    if stem.lower().endswith("_patch"):
        out_name = f"{stem}.apk"
    else:
        out_name = f"{stem}_patch.apk"
    log(f"[*] 输出文件名: {out_name}")

    # 3. apktool 解包
    unpack_dir = abi_work / "unpack"
    extract_with_apktool(original_apk, unpack_dir)

    # 4. 修改 MainActivity.smali
    main_activity = find_main_activity(unpack_dir)
    if main_activity:
        patch_main_activity(main_activity)
    else:
        log(f"[!] 未找到 {MAIN_ACTIVITY_REL}，跳过 smali 修改")

    # 5. 注入 .so
    abi_so_dir = SO_PATCH_DIR / abi
    if abi_so_dir.exists():
        inject_so_files(abi_so_dir, unpack_dir)
    else:
        inject_so_files(SO_PATCH_DIR, unpack_dir)

    # 6. apktool 打包
    rebuilt_apk = abi_work / "rebuilt.apk"
    repack_with_apktool(unpack_dir, rebuilt_apk)

    # 7. zipalign + 签名
    aligned_apk = abi_work / "aligned.apk"
    zipalign_apk(rebuilt_apk, aligned_apk)

    out_dir.mkdir(parents=True, exist_ok=True)
    out_apk = out_dir / out_name
    sign_apk(aligned_apk, out_apk)

    size_mb = out_apk.stat().st_size / 1024 / 1024
    sha256 = hashlib.sha256(out_apk.read_bytes()).hexdigest()
    log(f"[√] {channel}/{abi} 构建完成: {out_apk}  ({size_mb:.2f} MB)")
    log(f"    SHA256: {sha256}")
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

    # 状态
    state = load_state()
    local_so = state.get("so_tag", "")
    local_apks = state.get("apk_versions", {})
    log(f"[*] 本地状态: so={local_so or '(空)'}  apk={local_apks}")

    # SO 最新 release
    try:
        so_info = fetch_so_release_info()
        remote_so = so_info["tag"]
    except Exception as e:
        log(f"[!] 获取 so release 失败: {e}")
        so_info = {"tag": "", "assets": [], "matched": False}
        remote_so = ""

    so_changed = (
        bool(remote_so)
        and remote_so != local_so
        and bool(so_info["assets"])
    )

    # 逐个 channel 获取版本并比对
    jobs = []
    for ch in CHANNELS:
        try:
            info = fetch_version_info(ch["b"])
            parsed = parse_version_info(info)
        except Exception as e:
            log(f"[!] {ch['label']} 获取版本失败: {e}")
            continue

        remote_apk = str(parsed.get("version_all") or parsed["version"])
        local_apk = local_apks.get(ch["name"], "")
        apk_changed = remote_apk != local_apk

        log(f"[*] {ch['label']}({ch['name']}): 远程={remote_apk} "
            f"本地={local_apk or '(空)'} "
            f"{'变化' if apk_changed else '未变'}")

        if apk_changed or so_changed:
            jobs.append({
                "channel": ch,
                "remote_apk": remote_apk,
                "links": parsed["links"],
            })

    log(f"[*] SO: 远程={remote_so or '(无)'} 本地={local_so or '(空)'} "
        f"{'变化' if so_changed else '未变'}")

    if not jobs:
        log("[=] 所有 channel 均无更新，退出")
        return 0

    # 处理 so_patch（共用）
    if so_info["assets"] and (so_changed or not SO_PATCH_DIR.exists()):
        if SO_PATCH_DIR.exists():
            shutil.rmtree(SO_PATCH_DIR)
        SO_PATCH_DIR.mkdir(parents=True, exist_ok=True)
        download_so_assets(so_info["assets"], SO_PATCH_DIR)
    else:
        log(f"[*] 复用现有 so_patch（tag={remote_so}）")

    # 工作目录
    if WORK_DIR.exists():
        shutil.rmtree(WORK_DIR)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    # 逐 channel 逐 ABI 构建
    results: dict[str, list[Path]] = {}
    all_ok = True

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

    # 记录状态（全部成功才写）
    if all_ok:
        new_apks = dict(local_apks)
        for job in jobs:
            new_apks[job["channel"]["name"]] = job["remote_apk"]
        save_state({"so_tag": remote_so, "apk_versions": new_apks})
        log(f"[*] 已记录状态: so={remote_so} apk={new_apks}")
    else:
        log("[!] 存在失败项，不记录状态，下次将重试")

    # 汇总
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

    # 输出给 Actions
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
