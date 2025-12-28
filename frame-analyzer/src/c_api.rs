use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
    result::Result, // 导入标准Result类型
};
use libc::{c_int, c_uint}; // 移除未使用的c_ulonglong

use crate::{Analyzer, Pid};

static GLOBAL_ANALYZER: OnceLock<Arc<Mutex<Analyzer>>> = OnceLock::new();

#[repr(C)]
pub struct FrameTime {
    pub secs: c_uint,
    pub nanos: c_uint,
}

fn lock_analyzer(analyzer: &Arc<Mutex<Analyzer>>) -> Result<std::sync::MutexGuard<'_, Analyzer>, c_int> {
    match analyzer.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => Ok(poisoned.into_inner()),
    }
}

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

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_frametime(
    pid: c_int,
    timeout_ms: c_int,
    out_frametime: *mut FrameTime,
) -> c_int {
    if out_frametime.is_null() {
        return -1;
    }

    let pid = pid as Pid;
    let timeout = Duration::from_millis(timeout_ms as u64);

    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };

    let mut analyzer = match lock_analyzer(analyzer) {
        Ok(a) => a,
        Err(_) => return -1,
    };

    match analyzer.recv_timeout(timeout) {
        Some((recv_pid, frametime)) if recv_pid == pid => {
            let ft = FrameTime {
                secs: frametime.as_secs() as c_uint,
                nanos: frametime.subsec_nanos() as c_uint,
            };
            // 核心修复：将原始指针解引用放入unsafe块
            unsafe {
                *out_frametime = ft;
            }
            0
        }
        _ => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_detach(pid: c_int) -> c_int {
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
