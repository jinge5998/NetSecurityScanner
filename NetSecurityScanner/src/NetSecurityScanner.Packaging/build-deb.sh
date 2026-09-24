#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LINUX_PROJECT="$PROJECT_ROOT/NetSecurityScanner.Linux"
DEB_ROOT="$PROJECT_ROOT/output/deb-root"
OUTPUT_DIR="$PROJECT_ROOT/output"
VERSION="1.0.0"
ARCH="amd64"
PKG_NAME="net-security-scanner"
MAINTAINER="NetSecurityScanner Team <admin@example.com>"

echo "=== NetSecurityScanner Linux 打包工具 (deb) ==="
echo ""

# 清理
rm -rf "$DEB_ROOT" "$OUTPUT_DIR"/*.deb
mkdir -p "$DEB_ROOT/DEBIAN"
mkdir -p "$DEB_ROOT/opt/$PKG_NAME"
mkdir -p "$DEB_ROOT/usr/bin"
mkdir -p "$DEB_ROOT/usr/share/applications"
mkdir -p "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$DEB_ROOT/usr/share/doc/$PKG_NAME"

# 发布
echo "[1/4] 正在发布..."
dotnet publish "$LINUX_PROJECT/NetSecurityScanner.Linux.csproj" \
    --configuration Release \
    --runtime linux-x64 \
    --self-contained true \
    -o "$DEB_ROOT/opt/$PKG_NAME"

# 创建启动脚本
cat > "$DEB_ROOT/usr/bin/$PKG_NAME" << 'LAUNCHER'
#!/bin/bash
cd /opt/net-security-scanner
./NetSecurityScanner.Linux "$@"
LAUNCHER
chmod +x "$DEB_ROOT/usr/bin/$PKG_NAME"

# control 文件
echo "[2/4] 创建 deb 元数据..."
cat > "$DEB_ROOT/DEBIAN/control" << EOF
Package: $PKG_NAME
Version: $VERSION-1
Section: utils
Priority: optional
Architecture: $ARCH
Depends: libc6, libgcc-s1, libssl3, libicu70, zlib1g, libgssapi-krb5-2
Maintainer: $MAINTAINER
Description: Network Security Vulnerability Scanner
 A professional network security vulnerability scanning tool.
 Supports port scanning, vulnerability detection, risk assessment,
 and report generation (PDF/HTML).
 .
 Features:
  - Port service detection and banner grabbing
  - CVE vulnerability database lookup
  - AI-powered risk assessment
  - Plugin-based extensible architecture
  - Professional PDF security reports
Homepage: https://github.com/example/net-security-scanner
EOF

# postinst 脚本
cat > "$DEB_ROOT/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
echo "✅ NetSecurityScanner 已安装完成！"
echo "运行命令: net-security-scanner"
POSTINST
chmod 755 "$DEB_ROOT/DEBIAN/postinst"

# postrm 脚本
cat > "$DEB_ROOT/DEBIAN/postrm" << 'POSTRM'
#!/bin/sh
set -e
echo "🗑️ NetSecurityScanner 已卸载。"
POSTRM
chmod 755 "$DEB_ROOT/DEBIAN/postrm"

# .desktop 文件
echo "[3/4] 创建桌面入口..."
cat > "$DEB_ROOT/usr/share/applications/$PKG_NAME.desktop" << EOF
[Desktop Entry]
Version=$VERSION
Type=Application
Name=NetSecurity Scanner
Name[zh_CN]=网络安全漏洞扫描系统
GenericName=Security Scanner
GenericName[zh_CN]=安全扫描器
Comment=Network Security Vulnerability Scanner
Comment[zh_CN]=网络安全漏洞扫描工具
Exec=/usr/bin/$PKG_NAME
Icon=$PKG_NAME
Terminal=false
Categories=Network;Security;System;Utility;
Keywords=network;security;vulnerability;scanner;port;
StartupNotify=true
EOF

# copyright 文件
cat > "$DEB_ROOT/usr/share/doc/$PKG_NAME/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: NetSecurityScanner
Upstream-Contact: NetSecurityScanner Team <admin@example.com>
Source: https://github.com/example/net-security-scanner

License: MIT

Copyright: 2024 NetSecurityScanner Team
EOF

# 打包
echo "[4/4] 正在生成 deb 包..."
dpkg-deb --build "$DEB_ROOT" "$OUTPUT_DIR/${PKG_NAME}_${VERSION}-1_${ARCH}.deb"

echo ""
echo "✅ 完成!"
echo ""
ls -lh "$OUTPUT_DIR"/*.deb
echo ""
echo "安装方法:"
echo "  sudo dpkg -i ${PKG_NAME}_${VERSION}-1_${ARCH}.deb"
echo "  sudo apt-get install -f  # 如有依赖问题"
echo ""
echo "卸载方法:"
echo "  sudo dpkg -r $PKG_NAME"
