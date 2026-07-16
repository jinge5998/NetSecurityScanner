using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 端口管理服务，用于生成端口关闭脚本
    /// </summary>
    public class PortManagementService
    {
        /// <summary>
        /// 生成端口关闭脚本（标准版）
        /// </summary>
        public string GeneratePortClosureScript(List<int> portsToClose)
        {
            var script = new StringBuilder();
            script.AppendLine("@echo off");
            script.AppendLine("chcp 65001 >nul");
            script.AppendLine("color 0a");
            script.AppendLine("title 端口关闭脚本 - NetSecurityScanner");
            script.AppendLine("echo ====================================================");
            script.AppendLine("echo           端口关闭脚本 - NetSecurityScanner");
            script.AppendLine("echo ====================================================");
            script.AppendLine("echo.");
            script.AppendLine("echo [提示] 此脚本需要管理员权限运行！");
            script.AppendLine("echo [提示] 将以右键管理员身份重新运行...");
            script.AppendLine("echo.");
            script.AppendLine();
            
            script.AppendLine("REM 检查管理员权限");
            script.AppendLine("net session >nul 2>&1");
            script.AppendLine("if %errorLevel% neq 0 (");
            script.AppendLine("    echo [错误] 请以管理员身份运行此脚本！");
            script.AppendLine("    echo [操作] 右键点击脚本，选择\"以管理员身份运行\"");
            script.AppendLine("    echo.");
            script.AppendLine("    pause");
            script.AppendLine("    exit /b");
            script.AppendLine(")");
            script.AppendLine();
            
            script.AppendLine("echo [信息] 开始关闭指定端口...");
            script.AppendLine("echo.");
            
            foreach (int port in portsToClose)
            {
                string ruleNameInTcp = $"Block_Port{port}_TCP_In";
                string ruleNameInUdp = $"Block_Port{port}_UDP_In";
                
                script.AppendLine($"echo [端口 {port}] 添加防火墙规则...");
                script.AppendLine($"netsh advfirewall firewall add rule name=\"{ruleNameInTcp}\" dir=in action=block protocol=TCP localport={port} >nul 2>&1");
                script.AppendLine($"if %errorLevel% equ 0 (");
                script.AppendLine($"    echo [成功] 端口 {port} TCP入站规则已添加");
                script.AppendLine($") else (");
                script.AppendLine($"    echo [失败] 端口 {port} TCP入站规则添加失败");
                script.AppendLine($")");
                
                script.AppendLine($"netsh advfirewall firewall add rule name=\"{ruleNameInUdp}\" dir=in action=block protocol=UDP localport={port} >nul 2>&1");
                script.AppendLine($"if %errorLevel% equ 0 (");
                script.AppendLine($"    echo [成功] 端口 {port} UDP入站规则已添加");
                script.AppendLine($") else (");
                script.AppendLine($"    echo [失败] 端口 {port} UDP入站规则添加失败");
                script.AppendLine($")");
                
                script.AppendLine("echo.");
            }
            
            script.AppendLine("echo ====================================================");
            script.AppendLine("echo [完成] 端口关闭规则添加完成");
            script.AppendLine("echo [提示] 请重启相关服务使更改生效");
            script.AppendLine("echo ====================================================");
            script.AppendLine("echo.");
            script.AppendLine("pause");
            
            return script.ToString();
        }
        
        /// <summary>
        /// 生成端口关闭脚本（高级版）
        /// </summary>
        public string GenerateAdvancedPortClosureScript(List<int> portsToClose)
        {
            var script = new StringBuilder();
            script.AppendLine("@echo off");
            script.AppendLine("chcp 65001 >nul");
            script.AppendLine("color 0a");
            script.AppendLine("title 高级端口关闭脚本 - NetSecurityScanner");
            script.AppendLine("echo ====================================================");
            script.AppendLine("echo        高级端口关闭脚本 - NetSecurityScanner");
            script.AppendLine("echo ====================================================");
            script.AppendLine("echo.");
            script.AppendLine("echo [提示] 此脚本需要管理员权限运行！");
            script.AppendLine("echo.");
            script.AppendLine();
            
            script.AppendLine("REM 检查管理员权限");
            script.AppendLine("net session >nul 2>&1");
            script.AppendLine("if %errorLevel% neq 0 (");
            script.AppendLine("    echo [错误] 请以管理员身份运行此脚本！");
            script.AppendLine("    echo [操作] 右键点击脚本，选择\"以管理员身份运行\"");
            script.AppendLine("    echo.");
            script.AppendLine("    pause");
            script.AppendLine("    exit /b");
            script.AppendLine(")");
            script.AppendLine();
            
            script.AppendLine("echo [步骤 1/3] 备份当前防火墙规则...");
            script.AppendLine("set backupFile=FirewallBackup_%date:~0,4%%date:~5,2%%date:~8,2%_%time:~0,2%%time:~3,2%%time:~6,2%.wfw");
            script.AppendLine("set backupFile=%backupFile: =0%");
            script.AppendLine("netsh advfirewall export \"%backupFile%\" >nul 2>&1");
            script.AppendLine("if %errorLevel% equ 0 (");
            script.AppendLine("    echo [成功] 防火墙规则已备份至: %backupFile%");
            script.AppendLine(") else (");
            script.AppendLine("    echo [警告] 防火墙规则备份失败，继续执行...");
            script.AppendLine(")");
            script.AppendLine("echo.");
            script.AppendLine();
            
            script.AppendLine("echo [步骤 2/3] 关闭指定端口...");
            script.AppendLine("echo.");
            
            foreach (int port in portsToClose)
            {
                string ruleNameInTcp = $"Block_Port{port}_TCP_In";
                string ruleNameInUdp = $"Block_Port{port}_UDP_In";
                string ruleNameOutTcp = $"Block_Port{port}_TCP_Out";
                string ruleNameOutUdp = $"Block_Port{port}_UDP_Out";
                
                script.AppendLine($"echo [端口 {port}] 添加入站和出站防火墙规则...");
                
                script.AppendLine($"netsh advfirewall firewall add rule name=\"{ruleNameInTcp}\" dir=in action=block protocol=TCP localport={port} >nul 2>&1");
                script.AppendLine($"if %errorLevel% equ 0 (");
                script.AppendLine($"    echo [成功] 端口 {port} TCP入站规则已添加");
                script.AppendLine($") else (");
                script.AppendLine($"    echo [失败] 端口 {port} TCP入站规则添加失败");
                script.AppendLine($")");
                
                script.AppendLine($"netsh advfirewall firewall add rule name=\"{ruleNameInUdp}\" dir=in action=block protocol=UDP localport={port} >nul 2>&1");
                script.AppendLine($"if %errorLevel% equ 0 (");
                script.AppendLine($"    echo [成功] 端口 {port} UDP入站规则已添加");
                script.AppendLine($") else (");
                script.AppendLine($"    echo [失败] 端口 {port} UDP入站规则添加失败");
                script.AppendLine($")");
                
                script.AppendLine($"netsh advfirewall firewall add rule name=\"{ruleNameOutTcp}\" dir=out action=block protocol=TCP localport={port} >nul 2>&1");
                script.AppendLine($"if %errorLevel% equ 0 (");
                script.AppendLine($"    echo [成功] 端口 {port} TCP出站规则已添加");
                script.AppendLine($") else (");
                script.AppendLine($"    echo [失败] 端口 {port} TCP出站规则添加失败");
                script.AppendLine($")");
                
                script.AppendLine($"netsh advfirewall firewall add rule name=\"{ruleNameOutUdp}\" dir=out action=block protocol=UDP localport={port} >nul 2>&1");
                script.AppendLine($"if %errorLevel% equ 0 (");
                script.AppendLine($"    echo [成功] 端口 {port} UDP出站规则已添加");
                script.AppendLine($") else (");
                script.AppendLine($"    echo [失败] 端口 {port} UDP出站规则添加失败");
                script.AppendLine($")");
                
                script.AppendLine("echo.");
            }
            
            script.AppendLine("echo [步骤 3/3] 验证防火墙规则...");
            script.AppendLine("echo.");
            
            foreach (int port in portsToClose)
            {
                script.AppendLine($"echo [验证] 检查端口 {port} 的防火墙规则...");
                script.AppendLine($"netsh advfirewall firewall show rule name=\"Block_Port{port}_TCP_In\" >nul 2>&1");
                script.AppendLine($"if %errorLevel% equ 0 (");
                script.AppendLine($"    echo [通过] 端口 {port} 规则已生效");
                script.AppendLine($") else (");
                script.AppendLine($"    echo [警告] 端口 {port} 规则可能未生效");
                script.AppendLine($")");
            }
            
            script.AppendLine();
            script.AppendLine("echo ====================================================");
            script.AppendLine("echo [完成] 所有端口关闭规则添加完成");
            script.AppendLine("echo [提示] 防火墙规则已备份，如需恢复请运行：");
            script.AppendLine("echo        netsh advfirewall import \"备份文件名.wfw\"");
            script.AppendLine("echo [提示] 请重启相关服务使更改生效");
            script.AppendLine("echo ====================================================");
            script.AppendLine("echo.");
            script.AppendLine("pause");
            
            return script.ToString();
        }
        
        /// <summary>
        /// 保存脚本到桌面
        /// </summary>
        public string SaveScriptToFile(string scriptContent, string fileName)
        {
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string filePath = Path.Combine(desktopPath, fileName);
            
            File.WriteAllText(filePath, scriptContent, Encoding.UTF8);
            
            return filePath;
        }
    }
}