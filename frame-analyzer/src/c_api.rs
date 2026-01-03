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
    sync::{Arc, Mutex, Condvar, LazyLock},
    time::Duration,
    os::unix::io::RawFd,
    thread,
    collections::VecDeque,
};

use libc::{c_int, c_uint, c_void, eventfd, EFD_NONBLOCK, write, close};

use crate::{Analyzer, Pid};

/// 帧数据缓冲区：分离监听与读取逻辑，避免锁竞争
struct FrameBuffer {
    data: Mutex<VecDeque<(Pid, Duration)>>,
    cond: Condvar,
    lock: Mutex<()>,
}

impl FrameBuffer {
    /// 初始化帧缓冲区
    fn new() -> Self {
        Self {
            data: Mutex::new(VecDeque::with_capacity(1024)),
            cond: Condvar::new(),
            lock: Mutex::new(()),
        }
    }

    /// 写入帧数据并触发通知
    fn push(&self, pid: Pid, frametime: Duration) {
        let _lock = self.lock.lock().unwrap(); // 下划线标记未使用变量
        let mut data = self.data.lock().unwrap();
        data.push_back((pid, frametime));
        self.cond.notify_one();
    }

    /// 读取指定PID的帧数据（带超时）
    fn pop(&self, pid: Pid, timeout: Duration) -> Option<Duration> {
        let mut lock = self.lock.lock().unwrap(); // 保留mut，后续会被修改
        let _lock = self.cond.wait_timeout(lock, timeout).unwrap().0; // 下划线标记未使用变量
        
        let mut data = self.data.lock().unwrap();
        if let Some(pos) = data.iter().position(|(p, _)| *p == pid) {
            let (_, ft) = data.remove(pos).unwrap();
            Some(ft)
        } else {
            None
        }
    }
}

// 全局资源（延迟初始化避免静态变量调用非const函数）
static GLOBAL_ANALYZER: Mutex<Option<Arc<Mutex<Analyzer>>>> = Mutex::new(None);
static FRAME_BUFFER: LazyLock<Arc<FrameBuffer>> = LazyLock::new(|| Arc::new(FrameBuffer::new())); // 修正第72行的语法错误
static NOTIFY_FD: Mutex<Option<RawFd>> = Mutex::new(None);
static NOTIFY_THREAD: Mutex<Option<thread::JoinHandle<()>>> = Mutex::new(None);

/// C接口帧时间结构体
#[repr(C)]
pub struct FrameTime {
    pub secs: c_uint,
    pub nanos: c_uint,
}

/// 初始化EBPF和全局资源
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_init() -> c_int {
    let mut global = GLOBAL_ANALYZER.lock().unwrap();
    if global.is_some() {
        return 0;
    }

    // 初始化Analyzer
    let analyzer = match Analyzer::new() {
        Ok(a) => a,
        Err(_) => return -1,
    };

    // 创建eventfd（非阻塞模式）
    let efd = unsafe { eventfd(0, EFD_NONBLOCK) };
    if efd < 0 {
        return -1;
    }

    // 共享资源给后台线程
    let analyzer_arc = Arc::new(Mutex::new(analyzer));
    let analyzer_clone = analyzer_arc.clone();
    let efd_clone = efd;
    let buffer_clone = FRAME_BUFFER.clone();

    // 启动后台监听线程（非阻塞锁避免死锁）
    let thread = thread::spawn(move || {
        loop {
            let mut analyzer = match analyzer_clone.try_lock() {
                Ok(a) => a,
                Err(_) => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };

            // 读取帧数据并写入缓冲区
            if let Some((pid, ft)) = analyzer.recv_timeout(Duration::from_millis(50)) {
                buffer_clone.push(pid, ft);
                // 触发eventfd通知C++侧
                let val: u64 = 1;
                unsafe {
                    write(efd_clone, &val as *const u64 as *const c_void, 8);
                }
            }
        }
    });

    // 初始化全局资源
    *global = Some(analyzer_arc);
    *NOTIFY_FD.lock().unwrap() = Some(efd);
    *NOTIFY_THREAD.lock().unwrap() = Some(thread);

    0
}

/// 绑定目标PID的应用
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_attach(pid: c_int) -> c_int {
    let global = GLOBAL_ANALYZER.lock().unwrap();
    let analyzer = match global.as_ref() {
        Some(a) => a,
        None => return -1,
    };

    let pid = pid as Pid;
    let mut analyzer = match analyzer.try_lock() {
        Ok(a) => a,
        Err(_) => return -1,
    };

    analyzer.attach_app(pid).map_or(-1, |_| 0)
}

/// 获取指定PID的帧时间数据
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

    // 从缓冲区读取数据（避免直接操作Analyzer）
    match FRAME_BUFFER.pop(pid, timeout) {
        Some(frametime) => {
            let ft = FrameTime {
                secs: frametime.as_secs() as c_uint,
                nanos: frametime.subsec_nanos() as c_uint,
            };
            unsafe {
                *out_frametime = ft;
            }
            0
        }
        None => -1,
    }
}

/// 解绑目标PID的应用
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_detach(pid: c_int) -> c_int {
    let global = GLOBAL_ANALYZER.lock().unwrap();
    let analyzer = match global.as_ref() {
        Some(a) => a,
        None => return -1,
    };

    let pid = pid as Pid;
    let mut analyzer = match analyzer.try_lock() {
        Ok(a) => a,
        Err(_) => return -1,
    };

    analyzer.detach_app(pid).map_or(-1, |_| 0)
}

/// 销毁所有资源并终止后台线程
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_destroy() -> c_int {
    // 终止后台线程
    if let Some(thread) = NOTIFY_THREAD.lock().unwrap().take() {
        thread.thread().unpark();
    }

    // 清理Analyzer
    let mut global = GLOBAL_ANALYZER.lock().unwrap();
    if let Some(analyzer) = global.as_ref() {
        if let Ok(mut analyzer) = analyzer.try_lock() {
            analyzer.detach_apps();
        }
    }
    *global = None;

    // 关闭eventfd
    let mut notify_fd = NOTIFY_FD.lock().unwrap();
    if let Some(fd) = *notify_fd {
        unsafe { close(fd) };
    }
    *notify_fd = None;

    0
}

/// 获取事件通知FD（供C++侧epoll监听）
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_notify_fd() -> c_int {
    let guard = NOTIFY_FD.lock().unwrap();
    guard.as_ref().copied().unwrap_or(-1) as c_int
}

/// 废弃接口：Aya 0.13.1不支持RingBuf的as_raw_fd
#[deprecated(note = "Aya 0.13.1不支持该接口，改用frame_analyzer_get_notify_fd")]
#[unsafe(no_mangle)]
pub extern "C" fn frame_analyzer_get_ringbuf_fd(_pid: c_int) -> c_int {
    -1
}
