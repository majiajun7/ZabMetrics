#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAF Sender测试脚本
用于验证waf_sender.py的功能
"""

import subprocess
import sys
import json

def test_waf_sender():
    """测试WAF Sender功能"""
    
    # 测试参数
    waf_host = "https://192.168.1.100"  # 替换为实际的WAF地址
    token = "your_api_token"  # 替换为实际的API Token
    zabbix_server = "127.0.0.1"  # 替换为实际的Zabbix服务器地址
    zabbix_host = "WAF-Test"  # 替换为实际的Zabbix主机名
    
    print("WAF Sender测试")
    print("=" * 50)
    
    # 构建命令
    cmd = [
        sys.executable,
        "waf_sender.py",
        "--waf-host", waf_host,
        "--token", token,
        "--zabbix-server", zabbix_server,
        "--zabbix-host", zabbix_host,
        "--debug"
    ]
    
    print(f"执行命令: {' '.join(cmd)}")
    print("-" * 50)
    
    try:
        # 执行命令
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # 输出结果
        print("标准输出:")
        print(result.stdout)
        
        if result.stderr:
            print("\n标准错误:")
            print(result.stderr)
        
        print(f"\n返回码: {result.returncode}")
        
        if result.returncode == 0:
            print("\n✓ 测试成功！")
        else:
            print("\n✗ 测试失败！")
            
    except subprocess.TimeoutExpired:
        print("\n✗ 测试超时！")
    except Exception as e:
        print(f"\n✗ 测试出错: {e}")

def test_help():
    """测试帮助信息"""
    print("\n测试帮助信息")
    print("=" * 50)
    
    cmd = [sys.executable, "waf_sender.py", "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)

if __name__ == "__main__":
    # 首先测试帮助信息
    test_help()
    
    # 然后测试实际功能
    print("\n是否要测试实际功能？需要提供有效的WAF和Zabbix配置。")
    print("请修改脚本中的测试参数后再运行。")
    
    # 如果需要测试实际功能，取消下面的注释
    # test_waf_sender()