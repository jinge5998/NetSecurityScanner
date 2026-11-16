# NetSecurityScanner - Linux 版本

## 系统要求

- **操作系统**: Ubuntu 20.04+, Debian 11+, 或兼容的 x86_64 Linux 发行版
- **架构**: x86_64 (amd64)
- **运行时**: 自包含（无需单独安装 .NET Runtime）

## 安装方式

### 方式一：AppImage（推荐，无需安装）

```bash
chmod +x NetSecurityScanner-x86_64.AppImage
./NetSecurityScanner-x86_64.AppImage
```

### 方式二：deb 包（Ubuntu/Debian）

```bash
sudo dpkg -i net-security-scanner_1.0.0-1_amd64.deb
sudo apt-get install -f  # 自动安装缺失依赖
net-security-scanner      # 启动程序
```

### 方式三：tar.gz 通用压缩包

```bash
tar -xzf NetSecurityScanner-Linux-x64-1.0.0.tar.gz
./NetSecurityScanner.Linux
```

## 从源码构建

```bash
# 克隆项目
git clone <repository-url>
cd NetSecurityScanner

# 还原 NuGet 包
dotnet restore

# 发布 Linux 版本
dotnet publish src/NetSecurityScanner.Linux/NetSecurityScanner.Linux.csproj \
    -c Release \
    -r linux-x64 \
    --self-contained true

# 运行
./src/NetSecurityScanner.Linux/bin/Release/net8.0/linux-x64/publish/NetSecurityScanner.Linux
```

## 功能特性

- 📡 端口扫描与服务识别
- 🔍 CVE 漏洞数据库检测
- 🤖 AI 驱动的风险评估
- 📊 专业 PDF 安全报告生成
- 🔌 插件化扩展架构
- 📈 数据可视化图表
- 📋 扫描历史记录管理

## 已知限制

- 图表渲染基于 SkiaSharp，首次启动可能较慢
- Word 导出功能不可用（使用 PDF 替代）
- 部分高级 UI 效果可能与 WPF 版略有差异

## 故障排除

### 缺少中文字体

如果 PDF 报告中文显示异常，请安装中文字体：

```bash
# Ubuntu/Debian
sudo apt-get install fonts-noto-cjk

# Fedora
sudo dnf install google-noto-sans-cjk-fonts

# Arch Linux
sudo pacman -s noto-fonts-cjk
```

### 权限问题

```bash
# AppImage
chmod +x *.AppImage

# FUSE 问题（某些系统需要）
./AppImage --appimage-extract
./squashfs-root/AppRun
```

### 网络扫描需要 root 权限

部分端口扫描功能可能需要特权端口访问权限。
