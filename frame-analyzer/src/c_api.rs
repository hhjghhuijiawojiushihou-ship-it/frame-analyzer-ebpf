/*
* Copyright (c) 2024 shadow3aaa@gitbub.com
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use libc::{c_int, c_uint};

use crate::{Analyzer, Pid};

static GLOBAL_ANALYZER: OnceLock<Arc<Mutex<Analyzer>>> = OnceLock::new();

#[repr(C)]
pub struct FrameTime {
    pub secs: c_uint,
    pub nanos: c_uint,
}

fn lock_analyzer(analyzer: &Arc<Mutex<Analyzer>>) -> std::sync::MutexGuard<'_, Analyzer> {
    analyzer.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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
    GLOBAL_ANALYZER.set(Arc::new(Mutex::new(analyzer))).map_or(-1, |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_attach(pid: c_int) -> c_int {
    let analyzer = match GLOBAL_ANALYZER.get() {
        Some(a) => a,
        None => return -1,
    };
    let pid = pid as Pid;
    let mut analyzer = lock_analyzer(analyzer);
    analyzer.attach_app(pid).map_or(-1, |_| 0)
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
    let mut analyzer = lock_analyzer(analyzer);

    match analyzer.recv_timeout(timeout) {
        Some((recv_pid, frametime)) if recv_pid == pid => {
            let ft = FrameTime {
                secs: frametime.as_secs() as c_uint,
                nanos: frametime.subsec_nanos() as c_uint,
            };
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
    let mut analyzer = lock_analyzer(analyzer);
    analyzer.detach_app(pid).map_or(-1, |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_destroy() -> c_int {
    if let Some(analyzer) = GLOBAL_ANALYZER.get() {
        let mut analyzer = lock_analyzer(analyzer);
        analyzer.detach_apps();
    }
    0
}
