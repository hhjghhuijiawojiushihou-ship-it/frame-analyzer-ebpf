#!/bin/bash

# 目标目录路径
SRC_DIR="/storage/emulated/0/Download/frame-analyzer-ebpf-main"
# 输出文件路径
OUT_FILE="./ebpf.txt"

# 检查目标目录是否存在
if [ ! -d "$SRC_DIR" ]; then
    echo "错误：目录 $SRC_DIR 不存在！"
    exit 1
fi

# 清空输出文件（确保重新写入）
> "$OUT_FILE"

# 递归遍历目录下所有文件，写入路径和内容
find "$SRC_DIR" -type f | while read -r file; do
    echo "===== 【$file】 =====" >> "$OUT_FILE"
    cat "$file" >> "$OUT_FILE"
    echo -e "\n\n" >> "$OUT_FILE"
done

echo "操作完成！所有文件路径和内容已写入 $OUT_FILE"
