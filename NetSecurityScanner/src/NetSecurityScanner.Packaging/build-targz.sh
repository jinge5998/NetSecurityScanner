#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LINUX_PROJECT="$PROJECT_ROOT/NetSecurityScanner.Linux"
OUTPUT_DIR="$PROJECT_ROOT/output"
VERSION="1.0.0"

echo "=== NetSecurityScanner Linux 打包工具 (tar.gz) ==="
echo ""

# 清理旧的构建产物
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# 发布 Linux 版本
echo "[1/3] 正在发布 Linux 版本..."
dotnet publish "$LINUX_PROJECT/NetSecurityScanner.Linux.csproj" \
    --configuration Release \
    --runtime linux-x64 \
    --self-contained true \
    -p:PublishSingleFile=false \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -o "$OUTPUT_DIR/publish"

if [ $? -ne 0 ]; then
    echo "❌ 发布失败!"
    exit 1
fi

# 打包为 tar.gz
echo "[2/3] 正在打包..."
ARCHIVE_NAME="NetSecurityScanner-Linux-x64-$VERSION.tar.gz"
tar -czvf "$OUTPUT_DIR/$ARCHIVE_NAME" -C "$OUTPUT_DIR/publish" .

echo "[3/3] ✅ 完成!"
echo ""
echo "输出文件: $OUTPUT_DIR/$ARCHIVE_NAME"
FILESIZE=$(du -h "$OUTPUT_DIR/$ARCHIVE_NAME" | cut -f1)
echo "文件大小: $FILESIZE"
echo ""
echo "使用方法:"
echo "  1. 解压: tar -xzf $ARCHIVE_NAME"
echo "  2. 运行: ./NetSecurityScanner.Linux"
