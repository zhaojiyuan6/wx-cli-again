//! Windows 微信 4.1.11+ 密钥主路径：只读解析进程内 `Config.Cipher` 对象。
//!
//! 微信 4.1 起 raw key 不再以明文驻留内存（`wx key extract` 的 `x'<key><salt>'`
//! 字面量扫描通常 0 命中），但运行时 `Config.Cipher` 缓存对象里仍保存
//! `x'<64hex key><32hex salt>'`，只是按 32 字节掩码 XOR 过。本模块只读打开
//! `Weixin.exe` 内存，沿「类型名字符串对象 → 引用节点 → Config 指针 → blob」
//! 链路取出候选，再用每个数据库第一页的 HMAC 校验，命中才返回。
//!
//! 移植自 `wechat-local-vault/scripts/windows_keyscan.py`（MIT，源自 wcdb-key-tool）。
//! 全程只读：不注入、不调试、不暂停进程、不修改客户端或源数据库。
//! 因为不依赖特征码，微信小版本升级（4.1.x → 4.2.x）通常仍可用。

use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::{find_slice, is_writable_readable_page, KeyEntry};

/// 运行时 `Config.Cipher` 的类型名字符串。
const CONFIG_CIPHER_NEEDLE: &[u8] = b"com.Tencent.WCDB.Config.Cipher";
/// WeChat 4.1.x 构建里的 XOR 掩码。AMD64 / ARM64 可能不同：当 blob 为 99 字节时
/// 还会用数据库 salt 反推当前进程的实际掩码，因此不依赖这一份写死的值。
const CONFIG_XOR_MASK: [u8; 32] = [
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48, 0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
];
/// 单次 `ReadProcessMemory` / 内存块大小。
const READ_CHUNK: usize = 2 * 1024 * 1024;
/// 单个进程的内存读取预算，避免异常进程把扫描拖死。
const READ_BUDGET: u64 = 6 * 1024 * 1024 * 1024;
/// 用户态地址上限。
const MAX_USER_ADDRESS: usize = 0x0000_8000_0000_0000;
/// `Config.Cipher` blob 上限。
const CONFIG_BLOB_MAX: usize = 1024;
/// 节点里 Config 指针的偏移，以及 Config 对象里 blob 指针/长度的偏移。
const NODE_CONFIG_PTR_OFFSET: usize = 0x28;
const CONFIG_BLOB_OBJECT_OFFSET: usize = 0x88;
const BLOB_PTR_OFFSET: usize = 0x8;
const BLOB_LEN_OFFSET: usize = 0x10;

/// 可读页掩码：READONLY / READWRITE / WRITECOPY / EXECUTE_READ /
/// EXECUTE_READWRITE / EXECUTE_WRITECOPY。
fn is_readable_page(protect: u32) -> bool {
    let base = protect & !(0x100 | 0x200 | 0x400); // GUARD / NOCACHE / WRITECOMBINE
    matches!(base, 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80)
}

/// 一次 `Config.Cipher` 扫描的统计（用于日志，不含密钥）。
#[derive(Debug, Default, Clone)]
pub(crate) struct ConfigScanStats {
    pub needle: usize,
    pub nodes: usize,
    pub configs: usize,
    pub blob99: usize,
    pub candidates: usize,
    pub matched: usize,
    pub read_bytes: u64,
}

/// `Weixin.exe` 进程里的 `Weixin.dll` 模块信息。
pub(crate) struct WeixinModule {
    pub path: PathBuf,
    /// 从安装路径（如 `...\Weixin\4.2.0.50\Weixin.dll`）解析出的版本号。
    pub version: Option<String>,
}

/// 枚举指定进程的 `Weixin.dll` 模块。
///
/// 返回 `None` 表示该进程没有加载 `Weixin.dll`（微信 4.x 的 helper / render 子进程
/// 就没有），这类进程不持有 `Config.Cipher`，无需扫描内存，也无需 Frida attach。
pub(crate) fn weixin_module(pid: u32) -> Option<WeixinModule> {
    // SAFETY: CreateToolhelp32Snapshot 标准 Windows API
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
        .ok()?;

    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    let mut module = None;
    // SAFETY: Module32FirstW/Module32NextW 快照遍历
    unsafe {
        if Module32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name = utf16_field_to_string(&entry.szModule);
                if name.eq_ignore_ascii_case("Weixin.dll") {
                    let path = PathBuf::from(utf16_field_to_string(&entry.szExePath));
                    let version = version_from_install_path(&path);
                    module = Some(WeixinModule { path, version });
                    break;
                }
                if Module32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    module
}

/// 从安装路径里的版本目录解析版本号，如 `...\Tencent\Weixin\4.2.0.50\Weixin.dll`。
pub(crate) fn version_from_install_path(path: &Path) -> Option<String> {
    for component in path.components().rev() {
        let text = component.as_os_str().to_string_lossy();
        let parts: Vec<&str> = text.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 4 && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return Some(text.into_owned());
        }
    }
    None
}

fn utf16_field_to_string(field: &[u16]) -> String {
    let end = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    String::from_utf16_lossy(&field[..end])
}

/// 进程只读访问（`PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`）。
pub(crate) struct ProcessReader {
    handle: HANDLE,
    budget: u64,
    read_bytes: u64,
    exhausted: bool,
}

impl ProcessReader {
    pub(crate) fn open(pid: u32) -> Result<Self> {
        // SAFETY: OpenProcess 请求只读权限
        let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid) }
            .with_context(|| format!("OpenProcess 失败（PID {pid}），请以管理员权限运行"))?;
        Ok(Self {
            handle,
            budget: READ_BUDGET,
            read_bytes: 0,
            exhausted: false,
        })
    }

    pub(crate) fn read_bytes(&self) -> u64 {
        self.read_bytes
    }

    /// 读取一段内存；`size` 必须 ≤ 2 MiB。超出预算时返回错误并置 `exhausted`。
    pub(crate) fn read(&mut self, address: usize, size: usize) -> Result<Vec<u8>> {
        if size == 0 || size > READ_CHUNK {
            bail!("非法内存读取长度 {size}");
        }
        if self.read_bytes.saturating_add(size as u64) > self.budget {
            self.exhausted = true;
            bail!(
                "内存读取超过 {} GiB 预算，停止扫描",
                self.budget / 1024 / 1024 / 1024
            );
        }
        let mut buf = vec![0u8; size];
        let mut read: usize = 0;
        // SAFETY: ReadProcessMemory 读取目标进程内存
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const _,
                buf.as_mut_ptr() as *mut _,
                size,
                Some(&mut read),
            )
        };
        self.read_bytes = self.read_bytes.saturating_add(read as u64);
        result.with_context(|| format!("ReadProcessMemory 失败（地址 {address:#x}）"))?;
        buf.truncate(read);
        Ok(buf)
    }

    /// 读取失败时返回 `None`（页边界等场景很常见，不应中断整轮扫描）。
    fn read_opt(&mut self, address: usize, size: usize) -> Option<Vec<u8>> {
        match self.read(address, size) {
            Ok(buf) => Some(buf),
            Err(_) => None,
        }
    }

    /// 枚举已提交且可读的内存区域。
    ///
    /// `include_readonly` 为 `true` 时连只读页一起扫：`Config.Cipher` 的类型名字符串
    /// 位于模块 `.rdata`（只读），只扫可写堆页会一个都找不到。
    pub(crate) fn regions_of(&self, include_readonly: bool) -> Result<Vec<(usize, usize)>> {
        let mut addr: usize = 0;
        let mut out = Vec::new();
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: VirtualQueryEx 枚举进程内存区域
            let ret = unsafe {
                VirtualQueryEx(
                    self.handle,
                    Some(addr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if ret == 0 {
                break;
            }

            let base = mbi.BaseAddress as usize;
            let size = mbi.RegionSize;
            let scan = if include_readonly {
                is_readable_page(mbi.Protect.0)
            } else {
                is_writable_readable_page(mbi.Protect.0)
            };
            if mbi.State == MEM_COMMIT && scan {
                out.push((base, size));
            }

            let next = base.saturating_add(size);
            if next <= addr || next >= MAX_USER_ADDRESS {
                break;
            }
            addr = next;
        }
        Ok(out)
    }

    /// 按 `overlap` 重叠切块遍历区域；`on_chunk` 返回 `false` 时提前结束。
    pub(crate) fn for_each_chunk(
        &mut self,
        regions: &[(usize, usize)],
        overlap: usize,
        on_chunk: impl FnMut(usize, &[u8]) -> bool,
    ) -> Result<()> {
        let mut on_chunk = on_chunk;
        for &(base, size) in regions {
            let mut offset = 0usize;
            let mut tail: Vec<u8> = Vec::new();
            let mut tail_base = base;
            while offset < size {
                let len = READ_CHUNK.min(size - offset);
                let addr = base + offset;
                let chunk = match self.read(addr, len) {
                    Ok(chunk) => chunk,
                    Err(err) => {
                        if self.exhausted {
                            return Err(err);
                        }
                        Vec::new()
                    }
                };

                let (data_base, data) = if tail.is_empty() {
                    (addr, chunk)
                } else {
                    let mut joined = tail.clone();
                    joined.extend_from_slice(&chunk);
                    (tail_base, joined)
                };

                if !data.is_empty() {
                    if !on_chunk(data_base, &data) {
                        return Ok(());
                    }
                    let keep = overlap.min(data.len());
                    tail = data[data.len() - keep..].to_vec();
                    tail_base = data_base + data.len() - keep;
                } else {
                    tail.clear();
                }
                offset += len;
            }
        }
        Ok(())
    }
}

impl Drop for ProcessReader {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: 关闭自有句柄
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// 主路径：读取 `Config.Cipher` 对象并返回 HMAC 校验通过的密钥。
///
/// `db_salts` 为 `(salt_hex, db_rel_path)`；`remaining` 是尚未拿到密钥的库。
pub(crate) fn scan_config_cipher(
    pid: u32,
    db_dir: &Path,
    db_salts: &[(String, String)],
    remaining: &HashSet<String>,
) -> Result<(Vec<KeyEntry>, ConfigScanStats)> {
    let mut stats = ConfigScanStats::default();
    let mut found: Vec<KeyEntry> = Vec::new();
    if remaining.is_empty() {
        return Ok((found, stats));
    }

    let mut pending: HashSet<String> = remaining.clone();
    let mut salt_to_rels: HashMap<String, Vec<String>> = HashMap::new();
    for (salt, rel) in db_salts {
        if pending.contains(rel) {
            salt_to_rels
                .entry(salt.clone())
                .or_default()
                .push(rel.clone());
        }
    }
    if salt_to_rels.is_empty() {
        return Ok((found, stats));
    }
    let wanted_salts: HashSet<String> = salt_to_rels.keys().cloned().collect();

    let mut process = ProcessReader::open(pid)?;
    let regions = process.regions_of(true)?;

    // 1) 找到类型名字符串的所有出现位置。
    let mut needle_addresses: Vec<usize> = Vec::new();
    process.for_each_chunk(&regions, CONFIG_CIPHER_NEEDLE.len() - 1, |base, data| {
        let mut start = 0usize;
        while let Some(pos) = find_slice(&data[start..], CONFIG_CIPHER_NEEDLE) {
            needle_addresses.push(base + start + pos);
            start += pos + 1;
        }
        true
    })?;
    stats.needle = needle_addresses.len();
    if needle_addresses.is_empty() {
        stats.read_bytes = process.read_bytes();
        return Ok((found, stats));
    }

    // 2) 构造「字符串数据指针 + 长度」的引用模式。
    let needle_len = CONFIG_CIPHER_NEEDLE.len() as u64;
    let pair_patterns: Vec<[u8; 16]> = needle_addresses
        .iter()
        .map(|addr| {
            let mut pattern = [0u8; 16];
            pattern[..8].copy_from_slice(&(*addr as u64).to_le_bytes());
            pattern[8..].copy_from_slice(&needle_len.to_le_bytes());
            pattern
        })
        .collect();

    // 3) 先从内存里收集「字符串引用」地址，再逐个做结构化读取。
    //    分两趟是为了让读内存的闭包不再重入 `ProcessReader`（借用冲突），
    //    同时天然对同一节点去重。
    let mut qaddrs: Vec<usize> = Vec::new();
    let mut seen_q = HashSet::new();
    process.for_each_chunk(&regions, 0x80, |base, data| {
        for pattern in &pair_patterns {
            let mut start = 0usize;
            while let Some(pos) = find_slice(&data[start..], pattern) {
                let qaddr = base + start + pos;
                start += pos + 1;
                if seen_q.insert(qaddr) {
                    qaddrs.push(qaddr);
                }
            }
        }
        true
    })?;

    // 4) 引用节点 → Config 指针 → blob → 候选 key → 首页 HMAC 校验。
    let mut seen_nodes: HashSet<usize> = HashSet::new();
    let mut seen_configs: HashSet<usize> = HashSet::new();
    let mut seen_candidates: HashSet<(String, Option<String>)> = HashSet::new();
    for qaddr in qaddrs {
        let Some(node) = process.read_opt(qaddr - 0x10, 0x50) else {
            continue;
        };
        if node.len() < 0x40 || !needle_addresses.contains(&(read_u64(&node, 0x10) as usize)) {
            // 节点结构布局变化时宁可跳过，也不把任意 32 字节当密钥。
            continue;
        }
        if read_u64(&node, 0x18) != needle_len {
            continue;
        }
        seen_nodes.insert(qaddr);

        let config_ptr = read_u64(&node, NODE_CONFIG_PTR_OFFSET) as usize;
        if config_ptr < 0x10000 || config_ptr >= MAX_USER_ADDRESS {
            continue;
        }
        seen_configs.insert(config_ptr);

        let Some(object) = process.read_opt(config_ptr + CONFIG_BLOB_OBJECT_OFFSET, 0x28) else {
            continue;
        };
        if object.len() < 0x18 {
            continue;
        }
        let data_ptr = read_u64(&object, BLOB_PTR_OFFSET) as usize;
        let data_len = read_u64(&object, BLOB_LEN_OFFSET) as usize;
        if data_len == 0
            || data_len > CONFIG_BLOB_MAX
            || data_ptr < 0x10000
            || data_ptr >= MAX_USER_ADDRESS
        {
            continue;
        }
        let Some(blob) = process.read_opt(data_ptr, data_len) else {
            continue;
        };
        if blob.len() != data_len {
            continue;
        }
        if data_len == 99 {
            stats.blob99 += 1;
        }

        for (key_hex, embedded_salt) in config_key_candidates(&blob, &wanted_salts) {
            let candidate = (key_hex.clone(), embedded_salt.clone());
            if !seen_candidates.insert(candidate) {
                continue;
            }
            stats.candidates += 1;
            stats.matched += verify_candidate(
                &key_hex,
                embedded_salt.as_deref(),
                db_dir,
                &salt_to_rels,
                &mut pending,
                &mut found,
            );
        }
    }

    stats.nodes = seen_nodes.len();
    stats.configs = seen_configs.len();
    stats.read_bytes = process.read_bytes();
    Ok((found, stats))
}

/// 用候选 key 校验并匹配尚未覆盖的数据库；返回命中数量。
fn verify_candidate(
    key_hex: &str,
    embedded_salt: Option<&str>,
    db_dir: &Path,
    salt_to_rels: &HashMap<String, Vec<String>>,
    pending: &mut HashSet<String>,
    found: &mut Vec<KeyEntry>,
) -> usize {
    let Some(key) = super::decode_key_hex(key_hex) else {
        return 0;
    };

    // 有内嵌 salt 且该库仍缺密钥时优先只试这一个；否则用全部待匹配 salt。
    let embedded_pending = embedded_salt
        .and_then(|salt| salt_to_rels.get(salt))
        .map(|rels| rels.iter().any(|rel| pending.contains(rel)))
        .unwrap_or(false);
    let salts: Vec<&String> = match (embedded_pending, embedded_salt) {
        (true, Some(salt)) => salt_to_rels
            .get_key_value(salt)
            .map(|(key, _)| key)
            .into_iter()
            .collect(),
        _ => salt_to_rels.keys().collect(),
    };

    let mut matched = 0usize;
    for salt in salts {
        let Some(rels) = salt_to_rels.get(salt) else {
            continue;
        };
        for rel in rels {
            if !pending.contains(rel) {
                continue;
            }
            if crate::crypto::validate_raw_key_for_db(&db_dir.join(rel), &key) {
                pending.remove(rel);
                found.push(KeyEntry {
                    db_name: rel.clone(),
                    enc_key: key_hex.to_string(),
                    salt: salt.clone(),
                });
                matched += 1;
                break;
            }
        }
    }
    matched
}

/// 从 `Config.Cipher` blob 解出 `x'<key><salt>'` 候选。
///
/// blob 可能被固定掩码 XOR，也可能被当前构建自己的掩码 XOR；99 字节的 blob
/// 含完整一个 32 字节掩码周期，因此可以用数据库 salt 反推每个进程的实际掩码。
fn config_key_candidates(
    blob: &[u8],
    known_salts: &HashSet<String>,
) -> Vec<(String, Option<String>)> {
    if blob.is_empty() || blob.len() > CONFIG_BLOB_MAX {
        return Vec::new();
    }

    let mut masks: Vec<[u8; 32]> = vec![CONFIG_XOR_MASK];
    if blob.len() == 99 {
        for salt in known_salts {
            if salt.len() != 32 || !salt.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let mut mask = [0u8; 32];
            for (index, byte) in salt.as_bytes().iter().enumerate() {
                mask[(66 + index) % 32] = blob[66 + index] ^ byte;
            }
            if !masks.contains(&mask) {
                masks.push(mask);
            }
        }
    }

    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut seen: HashSet<(String, Option<String>)> = HashSet::new();
    for mask in &masks {
        let decoded: Vec<u8> = blob
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 32])
            .collect();
        for run in hex_literal_runs(&decoded) {
            let mut starts = vec![0usize];
            if run.len() > 96 {
                let mut start = 0usize;
                while start + 64 <= run.len() {
                    starts.push(start);
                    start += 32;
                }
                starts.push(run.len() - 64);
            }
            for start in starts {
                if start + 64 > run.len() {
                    continue;
                }
                let key_hex = run[start..start + 64].to_ascii_lowercase();
                let Some(key) = super::decode_key_hex(&key_hex) else {
                    continue;
                };
                let unique = key.iter().collect::<HashSet<_>>().len();
                if unique < 15 || key.iter().all(|&b| b == 0) || key.iter().all(|&b| b == 0xff) {
                    continue;
                }
                let embedded_salt = if start + 96 <= run.len() {
                    Some(run[start + 64..start + 96].to_ascii_lowercase())
                } else {
                    None
                };
                let item = (key_hex, embedded_salt);
                if seen.insert(item.clone()) {
                    out.push(item);
                }
            }
        }
    }
    out
}

/// 提取 `x'<hex...>'` 里连续十六进制串（不含引号）。
fn hex_literal_runs(data: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut index = 0usize;
    while index + 2 < data.len() {
        if (data[index] == b'x' || data[index] == b'X') && data[index + 1] == b'\'' {
            let mut end = index + 2;
            while end < data.len() && data[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end < data.len() && data[end] == b'\'' && end - (index + 2) >= 64 {
                runs.push(String::from_utf8_lossy(&data[index + 2..end]).into_owned());
            }
            index = end.max(index + 2);
        } else {
            index += 1;
        }
    }
    runs
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_with_mask(data: &[u8], mask: &[u8; 32]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 32])
            .collect()
    }

    #[test]
    fn recovers_literal_key_and_salt_from_fixed_mask() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let salt = "aabbccddeeff00112233445566778899";
        let literal = format!("x'{}{}'", key, salt);
        assert_eq!(literal.len(), 99);
        let blob = xor_with_mask(literal.as_bytes(), &CONFIG_XOR_MASK);

        let candidates = config_key_candidates(&blob, &HashSet::new());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, key);
        assert_eq!(candidates[0].1.as_deref(), Some(salt));
    }

    #[test]
    fn derives_mask_from_known_salt() {
        let key = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let salt = "00112233445566778899aabbccddeeff";
        let literal = format!("x'{}{}'", key, salt);
        let custom_mask = [0x5au8; 32];
        let blob = xor_with_mask(literal.as_bytes(), &custom_mask);

        let mut salts = HashSet::new();
        salts.insert(salt.to_string());
        let candidates = config_key_candidates(&blob, &salts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, key);
        assert_eq!(candidates[0].1.as_deref(), Some(salt));
    }

    #[test]
    fn rejects_low_entropy_and_bad_blobs() {
        assert!(config_key_candidates(&[], &HashSet::new()).is_empty());
        let zeros = vec![0u8; 99];
        assert!(config_key_candidates(&zeros, &HashSet::new()).is_empty());
        let too_big = vec![0u8; CONFIG_BLOB_MAX + 1];
        assert!(config_key_candidates(&too_big, &HashSet::new()).is_empty());
    }

    #[test]
    fn parses_version_from_install_path() {
        let path = Path::new(r"D:\Program Files\Tencent\Weixin\4.2.0.50\Weixin.dll");
        assert_eq!(version_from_install_path(path).as_deref(), Some("4.2.0.50"));
        let path = Path::new(r"C:\Users\me\AppData\Roaming\Tencent\xwechat\Weixin.dll");
        assert_eq!(version_from_install_path(path), None);
    }
}
