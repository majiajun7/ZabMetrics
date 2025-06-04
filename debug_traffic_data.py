#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
调试脚本：查看WAF流量API返回的实际数据结构
"""

import sys
import json
import time
import requests
import urllib3
from pprint import pprint

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def debug_traffic_api(waf_host, token, app_id, device_id):
    """调试流量API返回的数据"""
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    params = {
        "type": "mins",
        "app_id": app_id,
        "device_id": device_id,
        "_ts": int(time.time() * 1000)
    }
    
    url = f"{waf_host}/api/v1/logs/traffic/"
    
    print(f"请求URL: {url}")
    print(f"请求参数: {json.dumps(params, indent=2)}")
    print("-" * 80)
    
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=False,
            timeout=30
        )
        
        print(f"响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"响应代码: {data.get('code')}")
            
            if data.get("code") == "SUCCESS":
                results = data.get("data", {}).get("result", [])
                print(f"返回记录数: {len(results)}")
                
                if results:
                    print("\n第一条记录的完整结构:")
                    pprint(results[0])
                    
                    print("\n所有字段名称:")
                    for key in results[0].keys():
                        print(f"  - {key}: {results[0][key]}")
                    
                    # 检查是否有非"-"的数据
                    has_valid_data = False
                    for record in results:
                        for key, value in record.items():
                            if key != "timestamp" and value != "-":
                                has_valid_data = True
                                print(f"\n找到有效数据: {key} = {value}")
                                break
                        if has_valid_data:
                            break
                    
                    if not has_valid_data:
                        print("\n警告：所有数据字段都是'-'")
                else:
                    print("没有返回任何记录")
            else:
                print(f"API返回错误: {data}")
        else:
            print(f"HTTP错误: {response.status_code}")
            print(f"响应内容: {response.text}")
            
    except Exception as e:
        print(f"请求异常: {e}")

if __name__ == "__main__":
    # 测试参数
    waf_host = "https://10.21.30.5:8443"
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjQ4NzA1NzAwMzQsImlhdCI6MTc0ODUwNjAzNCwiaXNzIjoiV0FGX0FQSV9TRVJWRVIiLCJkYXRhIjp7InBrIjoiOWMwYmFiOWEtZGZiMC00OGMxLWEyZDQtOTljN2YxYzUzYmU0IiwidXNlcm5hbWUiOiJhZG1pbiJ9fQ.m0tOYXDSluBG5ObgVQ7Bl8Dib6aYAE08Pr81Ood8N4A"
    
    # 从日志中选一个有流量的站点测试
    app_id = "ac1977ad-9767-4e36-88e2-4324b56c5936"  # 3m平台-443
    device_id = "a72852d5-2a84-599f-8c69-790302ff8364"
    
    print("WAF流量数据调试")
    print("=" * 80)
    
    debug_traffic_api(waf_host, token, app_id, device_id)