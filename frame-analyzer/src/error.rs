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
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

use std::io;

use aya::{EbpfError, maps::MapError, programs::ProgramError};
use thiserror::Error;


pub type Result<T> = std::result::Result<T, AnalyzerError>;


#[derive(Error, Debug)]
pub enum AnalyzerError {
    /// Aya EBPF 加载/初始化错误
    #[error("EBPF error: {0}")]
    EbpfError(#[from] EbpfError),

    /// EBPF 程序（如UProbe）相关错误
    #[error("BPF program error: {0}")]
    BpfProgramError(#[from] ProgramError),

    /// EBPF Map 操作错误
    #[error("BPF map error: {0}")]
    BpfMapError(#[from] MapError),

    /// IO 操作错误
    #[error("IO error: {0}")]
    IOError(#[from] io::Error),

    /// 目标应用未找到（或附加失败）
    #[error("Application not found or attach failed")]
    AppNotFound,

    /// Map 不存在或获取失败
    #[error("BPF map not found or invalid")]
    MapError,
}
