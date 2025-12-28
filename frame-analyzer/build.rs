/*
* Copyright (c) 2024 shadow3aaa@gitbub.com
*
* This program is part of frame-analyzer-ebpf.
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
    env,
    fs,
    path::Path,
    process::Command,
};

use anyhow::{Context, Result}; // 替换Ok为Context，避免与std::result::Ok冲突

// 定义固定的eBPF文件路径
const EBPF_FILE_PATH: &str = "/workspaces/frame-analyzer-ebpf/ebpf_single_file/frame-analyzer-ebpf";

fn main() -> Result<()> {
    // 跳过原有的编译逻辑，直接验证并拷贝指定路径的eBPF文件
    copy_ebpf_file()?;
    Ok(())
}

/// 验证指定路径的eBPF文件是否存在，并拷贝到编译输出目录
fn copy_ebpf_file() -> Result<()> {
    let ebpf_src = Path::new(EBPF_FILE_PATH);
    // 检查文件是否存在
    if !ebpf_src.exists() {
        anyhow::bail!("eBPF文件不存在: {}", EBPF_FILE_PATH);
    }

    // 获取编译输出目录
    let out_dir = env::var("OUT_DIR").context("获取OUT_DIR环境变量失败")?;
    let out_dir = Path::new(&out_dir);
    let target_dir = out_dir.join("ebpf_target");
    let _target_dir_str = target_dir.to_str().context("转换目标目录路径为字符串失败")?; // 修复错误处理

    // 创建目标目录（兼容原代码的输出结构）
    #[cfg(debug_assertions)]
    let prefix_dir = target_dir.join("bpfel-unknown-none").join("debug"); // 移除多余的&，避免临时值引用
    #[cfg(not(debug_assertions))]
    let prefix_dir = target_dir.join("bpfel-unknown-none").join("release");

    fs::create_dir_all(&prefix_dir).context("创建eBPF目标目录失败")?;

    // 拷贝指定的eBPF文件到输出目录
    let ebpf_dst = prefix_dir.join("frame-analyzer-ebpf");
    fs::copy(ebpf_src, ebpf_dst).context("拷贝eBPF文件失败")?;
    println!("cargo:info=成功拷贝eBPF文件到: {}", prefix_dir.display());

    Ok(())
}

// 保留原代码中未使用的函数（如需后续扩展可启用）
#[allow(dead_code)]
fn add_path<S: AsRef<str>>(add: S) -> Result<String> {
    let path = env::var("PATH").context("获取PATH环境变量失败")?;
    Ok(format!("{path}:{}", add.as_ref()))
}

#[allow(dead_code)]
fn install_ebpf_linker() -> Result<()> {
    let out_dir = env::var("OUT_DIR").context("获取OUT_DIR环境变量失败")?;
    let out_dir = Path::new(&out_dir);
    let target_dir = out_dir.join("temp_target");
    let target_dir_str = target_dir.to_str().context("转换临时目录路径为字符串失败")?; // 修复命名，消除警告

    Command::new("cargo")
        .args([
            "install",
            "bpf-linker",
            "--force",
            "--root",
            target_dir_str,
            "--target-dir",
            target_dir_str,
        ])
        .status()
        .context("安装bpf-linker失败")?;

    Ok(())
}

#[allow(dead_code)]
fn build_ebpf() -> Result<()> {
    let current_dir = env::current_dir().context("获取当前工作目录失败")?;
    let project_path = current_dir.parent()
        .context("获取上级目录失败")?
        .join("frame-analyzer-ebpf");
    let out_dir = env::var("OUT_DIR").context("获取OUT_DIR环境变量失败")?;
    let out_dir = Path::new(&out_dir);
    let target_dir = out_dir.join("ebpf_target");
    let target_dir_str = target_dir.to_str().context("转换目标目录路径为字符串失败")?; // 修复命名，消除警告
    let bin = out_dir.join("temp_target").join("bin");
    let bin = bin.to_str().context("转换bin目录路径为字符串失败")?;

    if !target_dir.exists() {
        fs::create_dir(&target_dir).context("创建ebpf_target目录失败")?;
    }

    let mut ebpf_args = vec![
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir",
        target_dir_str,
    ];

    if project_path.exists() {
        println!("cargo:rerun-if-changed=../frame-analyzer-ebpf");

        #[cfg(not(debug_assertions))]
        ebpf_args.push("--release");

        Command::new("cargo")
            .arg("build")
            .args(ebpf_args)
            .env_remove("RUSTUP_TOOLCHAIN")
            .current_dir(&project_path)
            .env("PATH", add_path(bin)?)
            .status()
            .context("编译eBPF程序失败")?;
    } else {
        #[cfg(debug_assertions)]
        ebpf_args.push("--debug");

        let _ = fs::remove_dir_all(target_dir.join("bin")); // clean up
        let status = Command::new("cargo")
            .args(["install", "frame-analyzer-ebpf"])
            .arg("--force")
            .args(ebpf_args)
            .args(["--root", target_dir_str])
            .env_remove("RUSTUP_TOOLCHAIN")
            .env("PATH", add_path(bin)?)
            .status()
            .context("通过cargo install安装eBPF程序失败")?;
        
        if !status.success() {
            anyhow::bail!(
                "Critical: Failed to install frame-analyzer-ebpf via cargo install. Check the output above for linker errors."
            );
        }

        #[cfg(debug_assertions)]
        let prefix_dir = target_dir.join("bpfel-unknown-none").join("debug");

        #[cfg(not(debug_assertions))]
        let prefix_dir = target_dir.join("bpfel-unknown-none").join("release");

        let _ = fs::create_dir_all(&prefix_dir);
        let to = prefix_dir.join("frame-analyzer-ebpf");
        fs::rename(
            target_dir.join("bin").join("frame-analyzer-ebpf"),
            to
        ).context("重命名eBPF程序文件失败")?;
    }

    Ok(())
}
