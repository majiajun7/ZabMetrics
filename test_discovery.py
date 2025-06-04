#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试WAF站点发现，查看拓扑结构
"""

import json
import requests
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_tree_api(host, token):
    """测试tree API，查看返回的数据结构"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print("测试集群拓扑API...")
    
    # 测试反向代理类型
    for site_type in ['reverse']:
        print(f"\n=== 测试 {site_type} 类型的拓扑树 ===")
        url = f"{host}/api/v1/website/tree/{site_type}/"
        
        try:
            response = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    tree_data = data.get("data", [])
                    print(f"拓扑数据: {json.dumps(tree_data, indent=2, ensure_ascii=False)}")
                    
                    # 递归打印树结构
                    def print_tree(nodes, level=0):
                        for node in nodes:
                            indent = "  " * level
                            node_type = node.get("struct_type")
                            node_id = node.get("_pk")
                            node_name = node.get("name")
                            print(f"{indent}[{node_type}] {node_name} (ID: {node_id})")
                            
                            children = node.get("children", [])
                            if children:
                                print_tree(children, level + 1)
                    
                    print("\n树形结构：")
                    print_tree(tree_data)
                else:
                    print(f"API返回错误: {data}")
            else:
                print(f"HTTP错误: {response.status_code}")
                
        except Exception as e:
            print(f"请求异常: {e}")

if __name__ == "__main__":
    # 配置参数
    host = "https://10.21.30.5:8443"
    token = "YOUR_TOKEN_HERE"  # 请替换为实际的token
    
    test_tree_api(host, token)