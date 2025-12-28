// frame-analyzer/src/c_api.rs
use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use libc::{c_int, c_uint, c_ulonglong}; // 新增纳秒/秒对应的C类型

use crate::{Analyzer, Pid};

// 全局单例：仅维护 Analyzer 实例（无缓存）
static GLOBAL_ANALYZER: OnceLock<Arc<Mutex<Analyzer>>> = OnceLock::new();

/// 1. 新增：C语言兼容的帧时间结构体（对应Rust的Duration）
/// 用于传递原始帧时间（秒 + 纳秒，避免浮点数精度损失）
#[repr(C)] // 确保内存布局符合C语言规则
pub struct FrameTime {
    pub secs: c_uint,      // 秒数（无符号，帧时间不会为负）
    pub nanos: c_uint,     // 纳秒数（0-999,999,999）
}

/// 辅助函数：安全锁定 Mutex，处理 poisoned 情况
fn lock_analyzer(analyzer: &Arc<Mutex<Analyzer>>) -> Result<std::sync::MutexGuard<'_, Analyzer>, c_int> {
    match analyzer.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => Ok(poisoned.into_inner()), // 锁中毒降级
    }
}

/// 2. 初始化接口（无修改）
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_init() -> c_int {
    if GLOBAL_ANALYZER.get().is_some() {
        return 0;
    }
    let analyzer = match Analyzer::new() {
        Ok(a) => a,
        Err(_) => return -1,
    };
    match GLOBAL_ANALYZER.set(Arc::new(Mutex::new(analyzer))) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// 3. 绑定PID接口（无修改）
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_attach(pid: c_int) -> c_int {
    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };
    let pid = pid as Pid;
    let mut analyzer = match lock_analyzer(analyzer) {
        Ok(a) => a,
        Err(_) => return -1,
    };
    match analyzer.attach_app(pid) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// 4. 核心修改：获取帧时间接口（替换原frame_analyzer_get_fps）
/// 功能：返回原始帧时间（秒+纳秒），不做FPS换算
/// 参数：pid=目标PID，timeout_ms=超时时间，out_frametime=输出帧时间的指针（C侧传入结构体地址）
/// 返回值：0=成功，-1=失败（未初始化/无数据/PID不匹配/锁定失败）
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_frametime(
    pid: c_int,
    timeout_ms: c_int,
    out_frametime: *mut FrameTime, // 输出参数：C侧接收帧时间的结构体指针
) -> c_int {
    // 检查输出指针是否有效（C侧必须传入非空指针）
    if out_frametime.is_null() {
        return -1;
    }

    let pid = pid as Pid;
    let timeout = Duration::from_millis(timeout_ms as u64);

    // 获取全局Analyzer实例
    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };

    // 锁定实例
    let mut analyzer = match lock_analyzer(analyzer) {
        Ok(a) => a,
        Err(_) => return -1,
    };

    // 调用原版recv_timeout，获取原始帧时间（不做任何换算）
    match analyzer.recv_timeout(timeout) {
        Some((recv_pid, frametime)) if recv_pid == pid => {
            // 将Rust的Duration转为C的FrameTime结构体
            let ft = FrameTime {
                secs: frametime.as_secs() as c_uint,
                nanos: frametime.subsec_nanos() as c_uint,
            };
            // 安全写入C侧传入的指针（unsafe：直接操作内存）
            *out_frametime = ft;
            0 // 成功返回0
        }
        // 无数据/PID不匹配/超时 → 返回失败
        _ => -1,
    }
}

/// 5. 解绑PID接口（无修改）
#[unsafe(no_mangle)]
pub extern "C" fn frame frame_analyzer_detach(pid: c_int) -> c_int {
    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };
    let pid = pid as Pid;
    let mut analyzer = match lock_analyzer(analyzer) {
        Ok(a) => a,
        Err(_) => return -1,
    };
    match analyzer.detach_app(pid) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// 6. 销毁接口（无修改）
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_destroy() -> c_int {
    if let Some(analyzer) = GLOBAL_ANALYZER.get() {
        let mut analyzer = match lock_analyzer(analyzer) {
            Ok(a) => a,
            Err(_) => return 0,
        };
        analyzer.detach_apps();
    }
    0
}
