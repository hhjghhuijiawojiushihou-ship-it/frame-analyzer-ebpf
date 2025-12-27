// frame-analyzer/src/c_api.rs
use std::{
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::Duration,
};

use libc::{c_double, c_int};
use crate::{Analyzer, AnalyzerError, Pid};

// 全局单例：仅维护 Analyzer 实例（无缓存）
static GLOBAL_ANALYZER: OnceLock<Arc<Mutex<Analyzer>>> = OnceLock::new();

/// 辅助函数：安全锁定 Mutex，处理 poisoned 情况
fn lock_analyzer(analyzer: &Arc<Mutex<Analyzer>>) -> Result<impl std::ops::DerefMut<Target = Analyzer>, c_int> {
    match analyzer.lock() {
        Ok(guard) => Ok(guard),
        Err(PoisonError::new(guard)) => {
            // 发生 panic 后，仍尝试获取锁（安全降级）
            Ok(guard)
        }
    }
}

/// C 接口：初始化 Analyzer（仅需调用一次）
/// 返回值：0=成功，-1=失败（已初始化返回 0）
#[no_mangle]
pub extern "C" fn frame_analyzer_init() -> c_int {
    // 若已初始化，直接返回成功
    if GLOBAL_ANALYZER.get().is_some() {
        return 0;
    }

    // 初始化原有 Analyzer 实例（完全复用原有逻辑）
    let analyzer = match Analyzer::new() {
        Ok(a) => a,
        Err(_) => return -1,
    };

    GLOBAL_ANALYZER
        .set(Arc::new(Mutex::new(analyzer)))
        .map_err(|_| -1)
        .unwrap_or(0)
}

/// C 接口：绑定目标 PID（对齐原有 attach_app）
/// 参数：pid=目标进程 PID
/// 返回值：0=成功，-1=失败（未初始化/PID 无效/无权限）
#[no_mangle]
pub extern "C" fn frame_analyzer_attach(pid: c_int) -> c_int {
    // 检查是否已初始化
    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };

    let pid = pid as Pid;
    let mut analyzer = match lock_analyzer(analyzer) {
        Ok(a) => a,
        Err(_) => return -1,
    };

    // 直接调用原有 attach_app 接口（无修改）
    match analyzer.attach_app(pid) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// C 接口：执行一次，返回一次实时帧率（完全对齐原有逻辑）
/// 参数：pid=目标进程 PID，timeout_ms=超时时间（毫秒，0=非阻塞）
/// 返回值：帧率（fps），-1.0=无数据/失败/未初始化/锁定失败
#[no_mangle]
pub extern "C" fn frame_analyzer_get_fps(pid: c_int, timeout_ms: c_int) -> c_double {
    let pid = pid as Pid;
    let timeout = Duration::from_millis(timeout_ms as u64);

    // 获取全局 Analyzer 实例
    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1.0,
    };

    let mut analyzer = match lock_analyzer(analyzer) {
        Ok(a) => a,
        Err(_) => return -1.0,
    };

    // 调用原有 recv_timeout 接口（无缓存，实时获取）
    match analyzer.recv_timeout(timeout) {
        // 成功获取帧时间 → 转成帧率（1/帧时间），避免除零
        Some((recv_pid, frametime)) if recv_pid == pid => {
            let secs = frametime.as_secs_f64();
            if secs <= 0.0 {
                -1.0
            } else {
                (1.0 / secs) as c_double
            }
        }
        // 无数据/PID 不匹配 → 返回 -1.0
        _ => -1.0,
    }
}

/// C 接口：解绑目标 PID（对齐原有 detach_app）
/// 参数：pid=目标进程 PID
/// 返回值：0=成功，-1=失败（未初始化/锁定失败）
#[no_mangle]
pub extern "C" fn frame_analyzer_detach(pid: c_int) -> c_int {
    // 检查是否已初始化
    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };

    let pid = pid as Pid;
    let mut analyzer = match lock_analyzer(analyzer) {
        Ok(a) => a,
        Err(_) => return -1,
    };

    // 直接调用原有 detach_app 接口
    match analyzer.detach_app(pid) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// C 接口：销毁资源（程序退出时调用）
/// 返回值：0=成功（无论是否初始化）
#[no_mangle]
pub extern "C" fn frame_analyzer_destroy() -> c_int {
    if let Some(analyzer) = GLOBAL_ANALYZER.get() {
        let mut analyzer = match lock_analyzer(analyzer) {
            Ok(a) => a,
            Err(_) => return 0,
        };
        analyzer.detach_apps(); // 解绑所有 PID（原有接口）
    }
    0
}
