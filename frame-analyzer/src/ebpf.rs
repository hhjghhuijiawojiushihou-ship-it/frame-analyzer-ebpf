/*
 * Copyright (c) 2024 shadow3aaa@gitbub.com
 *
 * This file is part of frame-analyzer-ebpf.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use aya::{Ebpf, include_bytes_aligned};
use ctor::ctor;
use log::info; // 新增：导入日志模块
use crate::error::Result;

#[ctor]
fn ebpf_workround() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    info!("🔧 已调整 memlock 限制（适配旧内核 BPF 内存管理）"); // 新增：日志输出
}

pub fn load_bpf() -> Result<Ebpf> {
    info!("📥 开始加载 BPF 字节码..."); // 新增：日志输出
    // This will include eBPF object file as raw bytes at compile-time and load it at runtime.
    #[cfg(debug_assertions)]
    let bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf_target/bpfel-unknown-none/debug/frame-analyzer-ebpf"
    )))?;
    #[cfg(not(debug_assertions))]
    let bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf_target/bpfel-unknown-none/release/frame-analyzer-ebpf"
    )))?;

    info!("✅ BPF 字节码加载成功，已注入内核"); // 新增：日志输出
    Ok(bpf)
}
