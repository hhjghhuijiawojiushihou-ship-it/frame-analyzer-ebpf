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
                path::Path, // 修复：删除未使用的PathBuf导入
                    process::Command,
};

use anyhow::{Ok, Result};

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
                        let out_dir = env::var("OUT_DIR")?;
                            let out_dir = Path::new(&out_dir);
                                let target_dir = out_dir.join("ebpf_target");
                                    let _target_dir_str = target_dir.to_str().unwrap(); // 修复：重命名为_target_dir_str，消除未使用警告

                                        // 创建目标目录（兼容原代码的输出结构）
                                            #[cfg(debug_assertions)]
                                                let prefix_dir = &target_dir.join("bpfel-unknown-none").join("debug");
                                                    #[cfg(not(debug_assertions))]
                                                        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("release");
                                                            fs::create_dir_all(prefix_dir)?;

                                                                // 拷贝指定的eBPF文件到输出目录
                                                                    let ebpf_dst = prefix_dir.join("frame-analyzer-ebpf");
                                                                        fs::copy(ebpf_src, ebpf_dst)?;
                                                                            println!("cargo:info=成功拷贝eBPF文件到: {}", prefix_dir.display());

                                                                                Ok(())
            }

            // 保留原代码中未使用的函数（如需后续扩展可启用）
            #[allow(dead_code)]
            fn add_path<S: AsRef<str>>(add: S) -> Result<String> {
                    let path = env::var("PATH")?;
                        Ok(format!("{path}:{}", add.as_ref()))
            }

            #[allow(dead_code)]
            fn install_ebpf_linker() -> Result<()> {
                    let out_dir = env::var("OUT_DIR")?;
                        let out_dir = Path::new(&out_dir);
                            let target_dir = out_dir.join("temp_target");
                                let _target_dir_str = target_dir.to_str().unwrap(); // 修复：重命名为_target_dir_str，消除未使用警告

                                    Command::new("cargo")
                                            .args([
                                                            "install",
                                                                        "bpf-linker",
                                                                                    "--force",
                                                                                                "--root",
                                                                                                            _target_dir_str, // 使用重命名后的变量
                                                                                                                        "--target-dir",
                                                                                                                                    _target_dir_str, // 使用重命名后的变量
                                            ])
                                                    .status()?;

                                                        Ok(())
                                            }

                                            #[allow(dead_code)]
                                            fn build_ebpf() -> Result<()> {
                                                    let current_dir = env::current_dir()?;
                                                        let project_path = current_dir.parent().unwrap().join("frame-analyzer-ebpf");
                                                            let out_dir = env::var("OUT_DIR")?;
                                                                let out_dir = Path::new(&out_dir);
                                                                    let target_dir = out_dir.join("ebpf_target");
                                                                        let _target_dir_str = target_dir.to_str().unwrap(); // 修复：重命名为_target_dir_str，消除未使用警告
                                                                            let bin = out_dir.join("temp_target").join("bin");
                                                                                let bin = bin.to_str().unwrap();

                                                                                    if !target_dir.exists() {
                                                                                                fs::create_dir(&target_dir)?;
                                                                                    }

                                                                                        let mut ebpf_args = vec![
                                                                                                    "--target",
                                                                                                            "bpfel-unknown-none",
                                                                                                                    "-Z",
                                                                                                                            "build-std=core",
                                                                                                                                    "--target-dir",
                                                                                                                                            _target_dir_str, // 使用重命名后的变量
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
                                                                                                                                                                                                        .status()?;
                                                                                            } else {
                                                                                                        #[cfg(debug_assertions)]
                                                                                                                ebpf_args.push("--debug");

                                                                                                                        let _ = fs::remove_dir_all(target_dir.join("bin")); // clean up
                                                                                                                                let status = Command::new("cargo")
                                                                                                                                            .args(["install", "frame-analyzer-ebpf"])
                                                                                                                                                        .arg("--force")
                                                                                                                                                                    .args(ebpf_args)
                                                                                                                                                                                .args(["--root", _target_dir_str]) // 使用重命名后的变量
                                                                                                                                                                                            .env_remove("RUSTUP_TOOLCHAIN")
                                                                                                                                                                                                        .env("PATH", add_path(bin)?)
                                                                                                                                                                                                                    .status()?;
                                                                                                                                                                                                                            if !status.success() {
                                                                                                                                                                                                                                            panic!(
                                                                                                                                                                                                                                                                "Critical: Failed to install frame-analyzer-ebpf via cargo install. Check the output above for linker errors."
                                                                                                                                                                                                                                            );
                                                                                                                                                                                                                                        }

                                                                                                                                                                                                                                                #[cfg(debug_assertions)]
                                                                                                                                                                                                                                                        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("debug");

                                                                                                                                                                                                                                                                #[cfg(not(debug_assertions))]
                                                                                                                                                                                                                                                                        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("release");

                                                                                                                                                                                                                                                                                let _ = fs::create_dir_all(prefix_dir);
                                                                                                                                                                                                                                                                                        let to = &prefix_dir.join("frame-analyzer-ebpf");
                                                                                                                                                                                                                                                                                                fs::rename(target_dir.join("bin").join("frame-analyzer-ebpf"), to)?;
                                                                                                                                                                                                                                    }

                                                                                                                                                                                                                                        Ok(())
                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                
                                                                                                                                                                                                                                            )
                                                                                                                                                                                                                            }
                                                                                            }
                                                                                            }
                                                                                        ]
                                                                                    }
                                            }
                                            ])
            }
            }
                }
}
}
}