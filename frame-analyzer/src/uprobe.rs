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
use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::UProbe,
};
use log::{info, debug}; // 新增：导入日志模块
use crate::{ebpf::load_bpf, error::Result};

pub struct UprobeHandler {
    bpf: Ebpf,
}

impl Drop for UprobeHandler {
    fn drop(&mut self) {
        if let Ok(program) = self.get_program() {
            let _ = program.unload();
            info!("🔌 Uprobe 探针已卸载"); // 新增：日志输出
        }
    }
}

impl UprobeHandler {
    pub fn attach_app(pid: i32) -> Result<Self> {
        info!("📌 开始处理目标进程（PID: {}）的 Uprobe 挂载", pid); // 新增：日志输出
        
        // 加载 BPF 程序（依赖 ebpf.rs 的 load_bpf，会触发其日志）
        let mut bpf = load_bpf()?;
        info!("✅ BPF 程序加载完成，准备初始化 Uprobe"); // 新增：日志输出

        // 获取并加载 Uprobe 程序
        let program: &mut UProbe = bpf.program_mut("frame_analyzer_ebpf").unwrap().try_into()?;
        program.load()?;
        info!("✅ Uprobe 程序内核加载成功，准备附着到 libgui.so"); // 新增：日志输出

        // 尝试挂载优先函数，失败则挂载备用函数
        program.attach(
            Some("_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi"),
            0,
            "/system/lib64/libgui.so",
            Some(pid),
        ).or_else(|e1| {
            debug!("⚠️  优先函数挂载失败（错误：{:?}），尝试备用 queueBuffer 函数", e1); // 新增：日志输出
            program.attach(
                Some("_ZN7android7Surface11queueBufferEP19ANativeWindowBufferiPNS_24SurfaceQueueBufferOutputE"),
                0,
                "/system/lib64/libgui.so",
                Some(pid),
            )
        })?;

        info!("🎉 Uprobe 探针成功挂载到 PID: {} 的 /system/lib64/libgui.so", pid); // 新增：日志输出
        Ok(Self { bpf })
    }

    pub fn ring(&mut self) -> Result<RingBuf<&mut MapData>> {
        let ring: RingBuf<&mut MapData> = RingBuf::try_from(self.bpf.map_mut("RING_BUF").unwrap())?;
        Ok(ring)
    }

    fn get_program(&mut self) -> Result<&mut UProbe> {
        let program: &mut UProbe = self
            .bpf
            .program_mut("frame_analyzer_ebpf")
            .unwrap()
            .try_into()?;
        Ok(program)
    }
}
