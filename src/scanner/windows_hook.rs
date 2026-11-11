//! Windows 密钥 Hook 提取（微信 4.1.x）
//!
//! 微信 4.1 起，SQLCipher 的 32 字节 raw key 不再以明文长期驻留进程内存，
//! 纯内存扫描会 0 命中。这里改为在页加解密时抓取密钥：
//!
//! 1. 用特征码定位 Weixin.dll 内 SQLCipher 的页加解密包装函数
//!    （函数序言以 `push r14; push rsi; push rdi; push rbx; sub rsp,0x48;
//!    mov rdi,r8; mov ebx,edx; mov r14,rcx` 开头，跨版本稳定）；
//! 2. 该函数每次都会被调用，且入口第三个参数（r8）就是 32 字节 key，
//!    第 5 个参数（栈上）是 16 字节 IV；
//! 3. 通过 Frida 注入抓取，去重后交给调用方离线校验并映射到 DB 文件。
//!
//! 依赖：`pip install frida`（只用 frida 包，不需要 frida-tools）。

use anyhow::{bail, Context, Result};
use std::process::Command;

/// 默认 hook 等待秒数（给用户时间在微信里打开会话/历史，触发冷分片解密）。
pub const DEFAULT_HOOK_SECONDS: u64 = 90;

/// 特征码只在微信 4.1.x 的 `Weixin.dll` 上验证过；4.2+ 的函数序言已变，
/// 继续等满 hook 时间只会 0 命中。返回 `false` 时调用方应跳过 hook 并提示更新特征码。
pub(crate) fn signature_may_work(version: Option<&str>) -> bool {
    let Some(version) = version else {
        return true; // 版本未知：保留尝试
    };
    let numbers: Vec<u32> = version
        .split('.')
        .filter_map(|part| part.parse::<u32>().ok())
        .collect();
    match numbers.as_slice() {
        [major, minor, ..] => *major < 4 || (*major == 4 && *minor <= 1),
        _ => true,
    }
}

const HOOK_JS: &str = r#"
'use strict';

const MODULE = 'Weixin.dll';
const PATTERN = '41 56 56 57 53 48 83 ec 48 49 8b f8 89 d3 49 8b f1 48 8b 05';

const errs = [];
let base = null;
let found = [];

function locate() {
  let mod;
  try {
    mod = Process.getModuleByName(MODULE);
  } catch (e) {
    errs.push('module ' + MODULE + ' not found: ' + e.message);
    return;
  }
  base = mod.base;
  try {
    Memory.scan(mod.base, mod.size, PATTERN, {
      onMatch(a) {
        found.push(a);
        if (found.length >= 8) return 'stop';
      },
      onError(e) {},
      onComplete() {},
    });
  } catch (e) {
    errs.push('scan: ' + e.message);
  }
}

function hex(p, n) {
  try {
    if (p.isNull()) return null;
    return Array.from(new Uint8Array(p.readByteArray(n)))
      .map((b) => ('0' + b.toString(16)).slice(-2))
      .join('');
  } catch (e) {
    return null;
  }
}

let calls = 0;
const keys = {};

locate();
for (const addr of found) {
  try {
    Interceptor.attach(addr, {
      onEnter(args) {
        calls++;
        try {
          const keyPtr = args[2];
          let keyLen = 0;
          try {
            const cipher = args[0].readPointer();
            if (!cipher.isNull()) keyLen = cipher.add(8).readS32();
          } catch (e) {}
          const ivPtr = this.context.rsp.add(0x28).readPointer();
          const n = keyLen === 16 || keyLen === 32 ? keyLen : 32;
          const kh = hex(keyPtr, n);
          if (!kh) return;
          const ih = hex(ivPtr, 16);
          if (!keys[kh]) {
            keys[kh] = { key: kh, keyLen: keyLen, iv: ih, hits: 1 };
          } else {
            keys[kh].hits++;
          }
        } catch (e) {
          if (errs.length < 10) errs.push(String(e));
        }
      },
    });
  } catch (e) {
    errs.push('hook ' + addr + ': ' + e.message);
  }
}

rpc.exports = {
  dump() {
    return {
      base: base ? base.toString() : null,
      found: found.map((x) => x.toString()),
      calls: calls,
      keys: Object.keys(keys).map((k) => keys[k]),
      errs: errs,
    };
  },
};
"#;

const DRIVER_PY: &str = r#"
import json
import sys
import time
import frida

pids = [int(x) for x in sys.argv[1].split(',') if x.strip()]
secs = int(sys.argv[2])
js_path = sys.argv[3]
out_path = sys.argv[4]

js = open(js_path, encoding='utf-8').read()
sessions = []
for pid in pids:
    try:
        s = frida.attach(pid)
        sc = s.create_script(js)
        sc.load()
        sessions.append((pid, s, sc))
    except Exception as e:
        print('attach %d failed: %s' % (pid, e), file=sys.stderr)

end = time.time() + secs
while time.time() < end:
    time.sleep(0.5)

result = {'keys': [], 'sessions': []}
seen = set()
for pid, s, sc in sessions:
    try:
        d = sc.exports_sync.dump()
        result['sessions'].append({
            'pid': pid,
            'calls': d.get('calls'),
            'found': d.get('found'),
            'errs': d.get('errs'),
        })
        for k in d.get('keys', []):
            if k['key'] not in seen:
                seen.add(k['key'])
                result['keys'].append(k)
    except Exception as e:
        result['sessions'].append({'pid': pid, 'error': str(e)})
    try:
        s.detach()
    except Exception:
        pass

open(out_path, 'w', encoding='utf-8').write(json.dumps(result))
"#;

fn python_candidates() -> Vec<(String, Vec<String>)> {
    vec![
        ("python".to_string(), vec![]),
        ("python3".to_string(), vec![]),
        ("py".to_string(), vec!["-3".to_string()]),
    ]
}

fn python_has_frida(exe: &str, prefix: &[String]) -> bool {
    let mut cmd = Command::new(exe);
    cmd.args(prefix).arg("-c").arg("import frida");
    matches!(cmd.output(), Ok(o) if o.status.success())
}

/// 在给定 PID 列表上挂接抓取 key，返回去重后的 64 位 hex 候选。
pub fn hook_keys(pids: &[u32], seconds: u64) -> Result<Vec<String>> {
    if pids.is_empty() {
        bail!("没有可附加的 Weixin.exe 进程");
    }
    let (py, prefix) = python_candidates()
        .into_iter()
        .find(|(exe, pre)| python_has_frida(exe, pre))
        .context(
            "未找到可用的 Python + frida。请先执行：pip install frida\n\
             （只 hook 阶段需要；已捕获过的密钥会保存在 all_keys.json）",
        )?;

    let stamp = format!("{}-{}", std::process::id(), seconds);
    let dir = std::env::temp_dir().join("wx-cli-hook");
    std::fs::create_dir_all(&dir)?;
    let js_path = dir.join(format!("hook-{stamp}.js"));
    let py_path = dir.join(format!("driver-{stamp}.py"));
    let out_path = dir.join(format!("keys-{stamp}.json"));
    std::fs::write(&js_path, HOOK_JS)?;
    std::fs::write(&py_path, DRIVER_PY)?;

    let pid_arg = pids
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    eprintln!(
        "启动 Frida hook {}s（PID {}）：等待期间在微信中打开会话/历史以触发冷分片解密…",
        seconds, pid_arg
    );

    let mut cmd = Command::new(&py);
    cmd.args(&prefix)
        .arg(&py_path)
        .arg(&pid_arg)
        .arg(seconds.to_string())
        .arg(&js_path)
        .arg(&out_path);

    let mut child = cmd
        .spawn()
        .with_context(|| format!("启动 Python hook 失败: {py}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds + 120);
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            bail!("Frida hook 超时（{}s + 120s）", seconds);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    if !status.success() {
        bail!("Frida hook 进程退出异常: {status}");
    }

    let text = std::fs::read_to_string(&out_path)
        .with_context(|| format!("读取 hook 结果失败: {}", out_path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    if let Some(sessions) = v.get("sessions").and_then(|s| s.as_array()) {
        for s in sessions {
            let pid = s.get("pid").and_then(|x| x.as_u64()).unwrap_or(0);
            let calls = s.get("calls").and_then(|x| x.as_u64()).unwrap_or(0);
            let found = s
                .get("found")
                .and_then(|x| x.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if let Some(e) = s.get("error").and_then(|x| x.as_str()) {
                eprintln!("  PID {pid}: {e}");
            } else {
                eprintln!("  PID {pid}: 特征码命中 {found} 处，回调 {calls} 次");
            }
        }
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Some(keys) = v.get("keys").and_then(|k| k.as_array()) {
        for k in keys {
            let Some(h) = k.get("key").and_then(|x| x.as_str()) else {
                continue;
            };
            let h = h.to_lowercase();
            if h.len() == 64
                && h.chars().all(|c| c.is_ascii_hexdigit())
                && seen.insert(h.clone())
            {
                out.push(h);
            }
        }
    }

    let _ = std::fs::remove_file(&js_path);
    let _ = std::fs::remove_file(&py_path);
    let _ = std::fs::remove_file(&out_path);

    if out.is_empty() {
        bail!(
            "hook 未捕获到密钥：确认微信正在运行且 {}s 内有数据库读写（打开会话/收发消息）",
            seconds
        );
    }
    Ok(out)
}
