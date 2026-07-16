#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LINUX_PROJECT="$PROJECT_ROOT/NetSecurityScanner.Linux"
APPDIR="$PROJECT_ROOT/output/AppDir"
OUTPUT_DIR="$PROJECT_ROOT/output"
VERSION="1.0.0"
APP_NAME="NetSecurityScanner"

echo "=== NetSecurityScanner Linux 打包工具 (AppImage) ==="
echo ""

# 检查依赖
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ 缺少依赖: $1"
        echo "   安装方式: $2"
        exit 1
    fi
}

echo "[0/5] 检查依赖..."
check_dependency "linuxdeploy" "wget https://github.com/linuxdeploy/linux/releases/download/continuous/linuxdeploy-x86_64.AppImage && chmod +x linuxdeploy-x86_64.AppImage"
check_dependency "dotnet" "安装 .NET SDK: https://dotnet.microsoft.com/download"

# 清理旧文件
rm -rf "$APPDIR" "$OUTPUT_DIR"/*.AppImage
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# 发布应用
echo "[1/5] 正在发布 Linux 版本..."
dotnet publish "$LINUX_PROJECT/NetSecurityScanner.Linux.csproj" \
    --configuration Release \
    --runtime linux-x64 \
    --self-contained true \
    -p:PublishSingleFile=false \
    -o "$APPDIR/usr/bin"

# 复制运行时库到 lib 目录
cp -r "$APPDIR/usr/bin/"*.so* "$APPDIR/usr/lib/" 2>/dev/null || true

# 创建 .desktop 文件
echo "[2/5] 创建桌面入口..."
cat > "$APPDIR/usr/share/applications/${APP_NAME,,}.desktop" << EOF
[Desktop Entry]
Name=NetSecurity Scanner
Name[zh_CN]=网络安全漏洞扫描系统
Comment=Network Security Vulnerability Scanner
Comment[zh_CN]=网络安全漏洞扫描系统
Exec=${APP_NAME,,}
Icon=${APP_NAME,,}
Terminal=false
Type=Application
Categories=Network;Security;System;
StartupWMClass=${APP_NAME}
EOF

# 创建图标（如果存在）
if [ -f "$LINUX_PROJECT/Assets/netsec-icon.png" ]; then
    cp "$LINUX_PROJECT/Assets/netsec-icon.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/${APP_NAME,,}.png"
else
    # 生成一个简单的占位图标提示
    echo "⚠️ 未找到图标文件，请将 netsec-icon.png 放入 Linux 项目的 Assets/ 目录"
fi

# AppImage 打包
echo "[3/5] 正在生成 AppImage..."
export VERSION="$VERSION"
linuxdeploy --appdir "$APPDIR" \
    --output appimage \
    --desktop-file "$APPDIR/usr/share/applications/${APP_NAME,,}.desktop"

if [ $? -eq 0 ]; then
    mv *.AppImage "$OUTPUT_DIR/" 2>/dev/null || true
fi

echo "[4/5] 设置权限..."
find "$OUTPUT_DIR" -name "*.AppImage" -exec chmod +x {} \; 2>/dev/null || true

echo "[5/5] ✅ 完成!"
echo ""
ls -la "$OUTPUT_DIR"/*.AppImage 2>/dev/null || echo "⚠️ AppImage 文件未生成，请检查 linuxdeploy 配置"
echo ""
echo "使用方法:"
echo "  chmod +x ${APP_NAME,,}*.AppImage"
echo "  ./${APP_NAME,,}*.AppImage"
