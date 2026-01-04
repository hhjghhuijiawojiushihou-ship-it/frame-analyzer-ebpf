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

use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::UProbe,
};
use std::path::{Path, PathBuf};
use crate::{ebpf::load_bpf, error::Result, error::AnalyzerError};

// 抑制未使用代码警告（后续会使用则保留，否则可删除字段/方法）
#[allow(dead_code)]
pub struct UprobeHandler {
    bpf: Ebpf,
    pid: i32,
    libgui_path: PathBuf, // 仅用于重试附加的路径缓存
}

impl Drop for UprobeHandler {
    fn drop(&mut self) {
        // 自动卸载探针，释放eBPF资源（修正：添加合法注释标记）
        if let Ok(program) = self.get_program() {
            let _ = program.unload();
        }
    }
}

impl UprobeHandler {
    /// 核心：附加目标应用的queueBuffer Uprobe探针
    pub fn attach_app(pid: i32) -> Result<Self> {
        let mut bpf = load_bpf()?;
        // 加载并转换为Uprobe程序：直接用?，自动转换ProgramError
        let program: &mut UProbe = bpf.program_mut("frame_analyzer_ebpf")
            .ok_or(AnalyzerError::MapError)?
            .try_into()?; // 关键：移除map_err，利用#[from]自动转换
        program.load()?;

        // Android不同版本的queueBuffer符号适配（核心符号列表）
        let queue_buffer_symbols = [
            "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi",
            "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferiPNS_24SurfaceQueueBufferOutputE",
            "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferj",
            "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferjPNS_24SurfaceQueueBufferOutputE",
            "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferl",
            "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferlPNS_24SurfaceQueueBufferOutputE",
        ];

        // libgui.so路径适配（核心路径）
        let libgui_paths = [
            "/system/lib64/libgui.so",
            "/vendor/lib64/libgui.so",
        ];

        // 遍历路径和符号，尝试附加探针
        let mut target_lib_path = PathBuf::new();
        let mut attach_success = false;
        'outer: for &path in &libgui_paths {
            let lib_path = Path::new(path);
            if !lib_path.exists() {
                continue;
            }

            for &symbol in &queue_buffer_symbols {
                if program.attach(Some(symbol), 0, lib_path, Some(pid)).is_ok() {
                    target_lib_path = lib_path.to_path_buf();
                    attach_success = true;
                    break 'outer;
                }
            }
        }

        if !attach_success {
            return Err(AnalyzerError::AppNotFound);
        }

        Ok(Self {
            bpf,
            pid,
            libgui_path: target_lib_path,
        })
    }

    /// 核心：应用重启后重试附加探针
    #[allow(dead_code)] // 抑制方法未使用警告
    pub fn reattach(&mut self) -> Result<()> {
        // 提前缓存pid和libgui_path，避免借用冲突
        let pid = self.pid;
        let libgui_path = self.libgui_path.clone();

        let program = self.get_program()?;
        let _ = program.unload(); // 卸载旧探针

        // 重试核心符号
        let queue_buffer_symbols = [
            "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi",
            "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferiPNS_24SurfaceQueueBufferOutputE",
        ];

        // 尝试重新附加
        for &symbol in &queue_buffer_symbols {
            if program.attach(Some(symbol), 0, &libgui_path, Some(pid)).is_ok() {
                return Ok(());
            }
        }

        Err(AnalyzerError::AppNotFound)
    }

    /// 核心：获取eBPF的RingBuf，读取采集的帧数据
    pub fn ring(&mut self) -> Result<RingBuf<&mut MapData>> {
        let ring = RingBuf::try_from(self.bpf.map_mut("RING_BUF")
            .ok_or(AnalyzerError::MapError)?)?;
        Ok(ring)
    }

    /// 内部：获取Uprobe程序实例
    fn get_program(&mut self) -> Result<&mut UProbe> {
        let program = self.bpf.program_mut("frame_analyzer_ebpf")
            .ok_or(AnalyzerError::MapError)?;
        // 关键：移除map_err，直接用?自动转换
        let uprobe: &mut UProbe = program.try_into()?;
        Ok(uprobe)
    }
}
