#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
明御WAF站点自动发现脚本
用于Zabbix LLD（低级别发现）
"""

import sys
import json
import argparse
import requests
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WAFSiteDiscovery:
    def __init__(self, host, token):
        """
        初始化WAF客户端
        
        :param host: WAF管理地址
        :param token: API Token
        """
        self.host = host.rstrip('/')
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    
    def discover_sites(self):
        """
        发现所有站点
        
        :return: Zabbix LLD格式的JSON数据
        """
        try:
            # 获取站点列表
            url = f"{self.host}/api/v1/website/site/"
            params = {
                "page": 1,
                "per_page": 1000  # 获取尽可能多的站点
            }
            
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    sites = data.get("data", {}).get("result", [])
                    
                    # 构建Zabbix LLD格式的数据
                    discovery_data = {
                        "data": []
                    }
                    
                    for site in sites:
                        # 获取站点基本信息
                        site_info = {
                            "{#SITE_ID}": site.get("_pk", ""),
                            "{#SITE_NAME}": site.get("name", ""),
                            "{#SITE_TYPE}": site.get("type", ""),
                            "{#SITE_IP}": site.get("ip_set", ""),
                            "{#SITE_PORT}": ",".join(map(str, site.get("port", []))),
                            "{#SITE_DOMAIN}": ",".join(site.get("domain", [])),
                            "{#SITE_ENABLE}": "1" if site.get("enable", False) else "0",
                            "{#STRUCT_ID}": site.get("struct_pk", "")
                        }
                        
                        discovery_data["data"].append(site_info)
                    
                    return json.dumps(discovery_data, ensure_ascii=False)
                else:
                    raise Exception(f"API返回错误: {data.get('message', '未知错误')}")
            else:
                raise Exception(f"HTTP错误: {response.status_code}")
                
        except Exception as e:
            # Zabbix期望在错误时返回空的发现数据
            error_data = {
                "data": [],
                "error": str(e)
            }
            return json.dumps(error_data, ensure_ascii=False)
    
    def discover_devices(self):
        """
        发现设备信息（如果是集群环境）
        
        :return: Zabbix LLD格式的JSON数据
        """
        try:
            # 首先获取设备基本信息
            device_info_url = f"{self.host}/api/v1/device/info/"
            response = requests.get(
                device_info_url,
                headers=self.headers,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    device_data = data.get("data", {})
                    
                    # 构建设备发现数据
                    discovery_data = {
                        "data": [{
                            "{#DEVICE_ID}": device_data.get("serial", ""),
                            "{#DEVICE_VERSION}": device_data.get("version", ""),
                            "{#DEVICE_TYPE}": "standalone"  # 默认为独立设备
                        }]
                    }
                    
                    return json.dumps(discovery_data, ensure_ascii=False)
            
            # 如果无法获取设备信息，返回空数据
            return json.dumps({"data": []})
            
        except Exception as e:
            return json.dumps({"data": [], "error": str(e)})


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(description='明御WAF站点自动发现脚本')
    parser.add_argument('--host', required=True, help='WAF管理地址')
    parser.add_argument('--token', required=True, help='API Token')
    parser.add_argument('--type', choices=['sites', 'devices'], default='sites', 
                       help='发现类型：sites(站点) 或 devices(设备)')
    
    args = parser.parse_args()
    
    # 创建发现客户端
    discovery = WAFSiteDiscovery(host=args.host, token=args.token)
    
    # 执行发现
    if args.type == 'sites':
        print(discovery.discover_sites())
    else:
        print(discovery.discover_devices())


if __name__ == "__main__":
    main()