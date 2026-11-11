//! Windows 微信进程密钥提取。
//!
//! 三条路径按顺序执行，前一条配齐就不再走后面的：
//!
//! 1. **`Config.Cipher` 只读解析**（主路径）：直接读运行时缓存对象里的
//!    `x'<key><salt>'`，微信 4.1.11+ / 4.2+ 通用，不需要 Frida；
//! 2. **内存候选扫描**（回退）：`x'<key><salt>'` 字面量 + 堆上 key/salt 邻接；
//! 3. **Frida hook**（兜底）：特征码仅对 4.1.x 验证过，4.2+ 默认跳过并给出提示，
//!    避免每次都要等满 hook 时间才发现特征码失效。
//!
//! 使用 Windows API：
//! - CreateToolhelp32Snapshot + Process32Next: 枚举进程找 Weixin.exe
//! - OpenProcess / VirtualQueryEx / ReadProcessMemory: 只读进程内存
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::path::Path;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

use super::windows_hook;
use super::windows_keyscan::{self, ProcessReader};
use super::{
    collect_db_salts, collect_salt_adjacent_keys, decode_salt_hex, match_key_hexes,
    merge_key_entries, scan_key_patterns, KeyEntry, MAX_PATTERN_BYTES,
};

/// 查找所有 Weixin.exe 进程 PID（主进程 + helper 子进程）。
///
/// 微信 4.x 在 Windows 上会起多个 Weixin.exe 实例（主 UI 进程持有密钥缓存，
/// 其余为 helper/render 子进程）。这里枚举全部，后续再按是否加载 `Weixin.dll`
/// 筛掉不持有密钥的 helper。
pub(crate) fn find_wechat_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot 标准 Windows API
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return pids;
    };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    // SAFETY: Process32First/Process32Next 标准快照遍历
    unsafe {
        if Process32First(snap, &mut entry).is_err() {
            let _ = CloseHandle(snap);
            return pids;
        }
        loop {
            let name =
                std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
            if name.eq_ignore_ascii_case("Weixin.exe") {
                pids.push(entry.th32ProcessID);
            }
            if Process32Next(snap, &mut entry).is_err() {
                break;
            }
        }
        let _ = CloseHandle(snap);
    }
    pids
}

/// 选择真正持有密钥缓存的进程（加载了 `Weixin.dll` 的那些），并返回其版本。
fn key_bearing_processes(pids: &[u32]) -> Vec<(u32, Option<String>)> {
    let mut targets: Vec<(u32, Option<String>)> = Vec::new();
    for pid in pids {
        let Some(module) = windows_keyscan::weixin_module(*pid) else {
            continue;
        };
        if module.version.is_none() {
            eprintln!(
                "  PID {pid}: 加载了 Weixin.dll 但未能从安装路径解析版本（{}）",
                module.path.display()
            );
        }
        targets.push((*pid, module.version));
    }

    if targets.is_empty() {
        // 模块枚举失败时保守回退：全部扫描，版本未知（Frida 仍可用）。
        eprintln!("提示: 未能枚举 Weixin.dll 模块，回退到全部 Weixin.exe 进程");
        targets = pids.iter().map(|pid| (*pid, None)).collect();
    } else if targets.len() < pids.len() {
        eprintln!(
            "持有 Weixin.dll 的进程: {}（已跳过 {} 个 helper 子进程）",
            targets
                .iter()
                .map(|(pid, _)| pid.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            pids.len() - targets.len()
        );
    }
    targets
}

pub fn scan_keys_with_options(
    db_dir: &Path,
    hook_seconds: u64,
    auto_hook: bool,
    known: &[KeyEntry],
) -> Result<Vec<KeyEntry>> {
    let pids = find_wechat_pids();
    if pids.is_empty() {
        bail!("找不到 Weixin.exe 进程，请确认微信正在运行");
    }
    eprintln!(
        "Weixin.exe 进程 ({}): {}",
        pids.len(),
        pids.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());
    if db_salts.is_empty() {
        bail!("数据目录中没有加密的 .db 文件: {}", db_dir.display());
    }
    let total = db_salts.len();

    let targets = key_bearing_processes(&pids);
    let version = targets.first().and_then(|(_, version)| version.clone());
    match &version {
        Some(version) => eprintln!("Weixin.dll 版本: {version}"),
        None => eprintln!("Weixin.dll 版本: 未识别（按未知版本处理）"),
    }

    // 已有有效密钥先并入，避免已配齐时还去扫描/注入。
    let mut entries: Vec<KeyEntry> = known.to_vec();
    let mut remaining: HashSet<String> = db_salts
        .iter()
        .map(|(_, rel)| rel.clone())
        .collect();
    for entry in &entries {
        remaining.remove(&entry.db_name);
    }
    if !known.is_empty() {
        eprintln!(
            "已有 {} 个有效密钥，待补 {} 个",
            entries.len(),
            remaining.len()
        );
    }
    if remaining.is_empty() {
        eprintln!("已有密钥已覆盖全部 {} 个加密数据库", total);
        return Ok(merge_key_entries(&entries, &[]));
    }

    // ── Phase 1: Config.Cipher（主路径，无需 Frida） ─────────────────────
    eprintln!("[1/3] 读取运行时 Config.Cipher（只读，不注入）…");
    for (pid, _) in &targets {
        if remaining.is_empty() {
            break;
        }
        match windows_keyscan::scan_config_cipher(*pid, db_dir, &db_salts, &remaining) {
            Ok((found, stats)) => {
                eprintln!(
                    "  PID {pid}: needle={} nodes={} configs={} blob99={} 候选={} 命中={}（读取约 {:.1} MB）",
                    stats.needle,
                    stats.nodes,
                    stats.configs,
                    stats.blob99,
                    stats.candidates,
                    stats.matched,
                    stats.read_bytes as f64 / (1024.0 * 1024.0)
                );
                for entry in found {
                    remaining.remove(&entry.db_name);
                    entries.push(entry);
                }
            }
            Err(err) => eprintln!("  PID {pid}: Config.Cipher 扫描失败（{err:#}），跳过"),
        }
    }
    eprintln!("[1/3] 完成：{}/{} 个密钥", entries.len(), total);

    // ── Phase 2: 内存候选扫描（x'hex' 字面量 + salt 邻接） ───────────────
    if !remaining.is_empty() {
        let pending: Vec<(String, String)> = db_salts
            .iter()
            .filter(|(_, rel)| remaining.contains(rel))
            .cloned()
            .collect();
        let salt_bytes: Vec<[u8; 16]> = pending
            .iter()
            .filter_map(|(salt, _)| decode_salt_hex(salt))
            .collect();

        eprintln!("[2/3] 回退：内存候选扫描（x'hex' 字面量 + salt 邻接）…");
        let mut raw_keys: Vec<(String, String)> = Vec::new();
        let mut extra_keys: Vec<String> = Vec::new();
        let mut seen_extra: HashSet<String> = HashSet::new();

        for (pid, _) in &targets {
            let mut reader = match ProcessReader::open(*pid) {
                Ok(reader) => reader,
                Err(err) => {
                    eprintln!("  PID {pid}: OpenProcess 失败（{err:#}），跳过");
                    continue;
                }
            };
            let regions = match reader.regions_of(false) {
                Ok(regions) => regions,
                Err(err) => {
                    eprintln!("  PID {pid}: 枚举内存区域失败（{err:#}），跳过");
                    continue;
                }
            };
            let scanned = reader.for_each_chunk(&regions, MAX_PATTERN_BYTES, |_, buf| {
                scan_key_patterns(buf, &mut raw_keys);
                collect_salt_adjacent_keys(buf, &salt_bytes, &mut extra_keys, &mut seen_extra);
                true
            });
            eprintln!(
                "  PID {pid}: x'hex' 候选 {} 个，salt 邻接候选 {} 个（读取约 {:.1} MB）",
                raw_keys.len(),
                extra_keys.len(),
                reader.read_bytes() as f64 / (1024.0 * 1024.0)
            );
            if let Err(err) = scanned {
                eprintln!("  PID {pid}: 扫描中断（{err:#}）");
            }
        }

        // 合并两类候选再去按页校验（与 macOS 扫描器一致）。
        let mut all_key_hexes = super::unique_key_hexes(&raw_keys);
        for key in &extra_keys {
            if !all_key_hexes.iter().any(|existing| existing == key) {
                all_key_hexes.push(key.clone());
            }
        }
        for entry in match_key_hexes(db_dir, &all_key_hexes, &raw_keys, &pending) {
            remaining.remove(&entry.db_name);
            entries.push(entry);
        }
        eprintln!("[2/3] 完成：{}/{} 个密钥", entries.len(), total);
    }

    // ── Phase 3: Frida hook（兜底；特征码仅 4.1.x 验证过） ────────────────
    if !remaining.is_empty() && auto_hook && hook_seconds > 0 {
        let hook_pids: Vec<u32> = targets.iter().map(|(pid, _)| *pid).collect();
        if !windows_hook::signature_may_work(version.as_deref()) {
            eprintln!(
                "[3/3] 跳过 Frida 特征码 hook：Weixin.dll {} 超出已验证的 4.1.x 范围（特征码随版本变化），\n\
                 继续等满 {}s 也只会 0 命中。",
                version.as_deref().unwrap_or("未知版本"),
                hook_seconds
            );
            eprintln!(
                "      请优先使用主路径 Config.Cipher；若它也没命中，需要更新 windows_hook.rs 的特征码。"
            );
        } else {
            let pending: Vec<(String, String)> = db_salts
                .iter()
                .filter(|(_, rel)| remaining.contains(rel))
                .cloned()
                .collect();
            eprintln!(
                "[3/3] 仍有 {} 个数据库未匹配密钥，启动 Frida hook {}s…\n\
                 请在此期间切换到微信：滚动聊天列表、打开几个会话/历史记录，\n\
                 以触发冷分片 DB 的解密（message_N.db 等）。",
                pending.len(),
                hook_seconds
            );
            match windows_hook::hook_keys(&hook_pids, hook_seconds) {
                Ok(hooked) => {
                    eprintln!("Frida hook 捕获到 {} 个 32-byte key", hooked.len());
                    let hooked_entries = match_key_hexes(db_dir, &hooked, &[], &pending);
                    eprintln!("hook 阶段新匹配到 {} 个数据库密钥", hooked_entries.len());
                    for entry in hooked_entries {
                        remaining.remove(&entry.db_name);
                        entries.push(entry);
                    }
                }
                Err(err) => {
                    eprintln!("Frida hook 未成功: {err:#}");
                    eprintln!("提示: 需要 Python 3 + frida（pip install frida）；微信需保持运行。");
                }
            }
        }
    }

    let entries = merge_key_entries(&entries, &[]);
    eprintln!(
        "最终匹配到 {}/{} 个数据库密钥",
        entries.len(),
        total
    );
    Ok(entries)
}
