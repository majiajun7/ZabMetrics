#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""调试Zabbix Sender问题"""

import subprocess
import json
import tempfile
import os

def test_single_item(server, host, key, value):
    """测试单个监控项"""
    print(f"\n测试发送数据:")
    print(f"  服务器: {server}")
    print(f"  主机: {host}")
    print(f"  键: {key}")
    print(f"  值: {value}")
    
    cmd = [
        'zabbix_sender',
        '-z', server,
        '-s', host,
        '-k', key,
        '-o', str(value),
        '-vv'
    ]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    print(f"\n输出:\n{result.stdout}")
    if result.stderr:
        print(f"错误:\n{result.stderr}")
    
    return "processed: 1" in result.stdout

def test_discovery_data(server, host):
    """测试LLD数据"""
    discovery_data = {
        "data": [
            {
                "{#SITE_ID}": "test-site-001",
                "{#SITE_NAME}": "测试站点",
                "{#STRUCT_ID}": "test-struct-001"
            }
        ]
    }
    
    return test_single_item(server, host, "waf.sites.discovery", json.dumps(discovery_data))

def test_status_data(server, host):
    """测试状态数据"""
    return test_single_item(server, host, "waf.site.status[测试站点]", "1")

def check_file_content(file_path):
    """检查临时文件内容"""
    print(f"\n检查文件内容: {file_path}")
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            content = f.read()
            print("文件内容:")
            print("-" * 50)
            print(content[:1000])  # 只显示前1000字符
            print("-" * 50)
    else:
        print("文件不存在")

def main():
    server = "10.21.30.4"
    host = "10.21.30.5"
    
    print("=" * 60)
    print("Zabbix Sender 调试工具")
    print("=" * 60)
    
    # 测试1: 基本连接
    print("\n1. 测试基本连接")
    test_single_item(server, host, "agent.ping", "1")
    
    # 测试2: LLD数据
    print("\n2. 测试LLD数据")
    if test_discovery_data(server, host):
        print("✓ LLD数据发送成功")
    else:
        print("✗ LLD数据发送失败")
    
    # 测试3: 普通监控项
    print("\n3. 测试普通监控项")
    if test_status_data(server, host):
        print("✓ 状态数据发送成功")
    else:
        print("✗ 状态数据发送失败")
    
    # 建议
    print("\n" + "=" * 60)
    print("可能的问题:")
    print("1. 检查Zabbix中主机名是否为:", host)
    print("2. 检查主机是否由Proxy监控")
    print("3. 检查是否已导入并应用模板")
    print("4. 运行: zabbix_proxy -R config_cache_reload")
    print("5. 查看Proxy日志: tail -f /var/log/zabbix/zabbix_proxy.log")

if __name__ == '__main__':
    main()