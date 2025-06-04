#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
明御WAF站点自动发现脚本
用于Zabbix LLD（低级别发现）
"""

import sys
import json
import time
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
    
    def get_device_mapping(self):
        """
        获取设备ID映射关系
        使用 /api/v1/device/name/ 接口获取设备ID
        
        :return: dict，key为app_id，value为实际的device_id
        """
        mapping = {}
        
        try:
            # 从 /api/v1/device/name/ 接口获取设备ID
            device_name_url = f"{self.host}/api/v1/device/name/"
            params = {"_ts": int(time.time() * 1000)}
            
            response = requests.get(
                device_name_url,
                headers=self.headers,
                params=params,
                verify=False,
                timeout=10
            )
            
            device_id = None
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    device_id = data.get("data", {}).get("id")
            
            # 如果成功获取到device_id，为所有站点使用这个ID
            if device_id:
                # 获取所有站点
                site_url = f"{self.host}/api/v1/website/site/"
                site_params = {"page": 1, "per_page": 1000}
                site_response = requests.get(
                    site_url,
                    headers=self.headers,
                    params=site_params,
                    verify=False,
                    timeout=10
                )
                
                if site_response.status_code == 200:
                    site_data = site_response.json()
                    if site_data.get("code") == "SUCCESS":
                        sites = site_data.get("data", {}).get("result", [])
                        for site in sites:
                            site_id = site.get("_pk")
                            if site_id:
                                mapping[site_id] = device_id
                
        except Exception:
            pass
        
        return mapping
    
    def find_device_id_for_site(self, app_id, debug=False):
        """
        为特定站点查找正确的device_id
        使用 /api/v1/device/name/ 接口获取设备ID
        
        :param app_id: 站点ID
        :param debug: 是否启用调试输出
        :return: device_id (UUID格式) 或 None
        """
        try:
            # 从 /api/v1/device/name/ 接口获取设备ID
            device_name_url = f"{self.host}/api/v1/device/name/"
            params = {"_ts": int(time.time() * 1000)}
            
            response = requests.get(
                device_name_url,
                headers=self.headers,
                params=params,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    device_id = data.get("data", {}).get("id")
                    if device_id:
                        if debug:
                            print(f"[DEBUG] 从/api/v1/device/name/接口获取到device_id: {device_id}")
                        # 可选：验证这个device_id是否能获取到流量数据
                        if app_id:  # 只有提供了app_id才验证
                            traffic_url = f"{self.host}/api/v1/logs/traffic/"
                            test_params = {
                                "type": "mins",
                                "app_id": app_id,
                                "device_id": device_id,
                                "_ts": int(time.time() * 1000)
                            }
                            try:
                                test_response = requests.get(
                                    traffic_url,
                                    headers=self.headers,
                                    params=test_params,
                                    verify=False,
                                    timeout=5
                                )
                                if test_response.status_code == 200:
                                    test_data = test_response.json()
                                    if test_data.get("code") == "SUCCESS":
                                        if debug:
                                            print(f"[DEBUG] device_id验证成功，可以获取流量数据")
                                        return device_id
                            except:
                                # 即使验证失败，也返回获取到的device_id
                                if debug:
                                    print(f"[DEBUG] device_id验证失败，但仍使用该ID")
                                return device_id
                        else:
                            return device_id
        except Exception as e:
            if debug:
                print(f"[DEBUG] 获取device_id失败: {e}")
        
        # 如果无法获取，返回默认值
        if debug:
            print(f"[DEBUG] 使用默认device_id: a72852d5-2a84-599f-8c69-790302ff8364")
        return "a72852d5-2a84-599f-8c69-790302ff8364"
    
    def discover_sites(self, debug=False):
        """
        发现所有站点
        
        :param debug: 是否启用调试输出
        :return: Zabbix LLD格式的JSON数据
        """
        try:
            # 构建站点ID到实际device_id的映射
            site_device_mapping = {}
            
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
                    
                    # 先为每个站点查找正确的device_id
                    if debug:
                        print(f"[DEBUG] 发现 {len(sites)} 个站点")
                    
                    for site in sites:
                        site_id = site.get("_pk", "")
                        site_name = site.get("name", "")
                        struct_pk = site.get("struct_pk", "")
                        
                        if debug:
                            print(f"[DEBUG] 处理站点: {site_name} (ID: {site_id}, struct_pk: {struct_pk})")
                        
                        # 如果struct_pk是"0"（全局配置），需要查找实际的device_id
                        if struct_pk == "0":
                            actual_device_id = self.find_device_id_for_site(site_id, debug)
                            if actual_device_id:
                                site_device_mapping[site_id] = actual_device_id
                                if debug:
                                    print(f"[DEBUG] 站点 {site_name} 使用device_id: {actual_device_id}")
                            else:
                                # 如果找不到，尝试通过实际请求流量API来探测
                                test_url = f"{self.host}/api/v1/logs/traffic/"
                                
                                # 尝试一些常见的device_id格式
                                for test_id in [site_id, struct_pk]:
                                    if test_id and test_id != "0":
                                        test_params = {
                                            "type": "mins",
                                            "app_id": site_id,
                                            "device_id": test_id,
                                            "_ts": int(time.time() * 1000)
                                        }
                                        try:
                                            test_response = requests.get(
                                                test_url,
                                                headers=self.headers,
                                                params=test_params,
                                                verify=False,
                                                timeout=5
                                            )
                                            if test_response.status_code == 200:
                                                test_data = test_response.json()
                                                if test_data.get("code") == "SUCCESS":
                                                    result = test_data.get("data", {}).get("result", [])
                                                    if result and any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
                                                        site_device_mapping[site_id] = test_id
                                                        break
                                        except:
                                            pass
                        else:
                            # struct_pk不是"0"，直接使用
                            site_device_mapping[site_id] = struct_pk
                            if debug:
                                print(f"[DEBUG] 站点 {site_name} 使用struct_pk作为device_id: {struct_pk}")
                    
                    # 构建Zabbix LLD格式的数据
                    discovery_data = {
                        "data": []
                    }
                    
                    for site in sites:
                        site_id = site.get("_pk", "")
                        site_type = site.get("type", "")
                        struct_pk = site.get("struct_pk", "")
                        
                        # 使用之前找到的device_id
                        effective_device_id = site_device_mapping.get(site_id, struct_pk)
                        
                        # 获取站点基本信息
                        site_info = {
                            "{#SITE_ID}": site_id,
                            "{#SITE_NAME}": site.get("name", ""),
                            "{#SITE_TYPE}": site_type,
                            "{#SITE_IP}": site.get("ip_set", ""),
                            "{#SITE_PORT}": ",".join(map(str, site.get("port", []))),
                            "{#SITE_DOMAIN}": ",".join(site.get("domain", [])),
                            "{#SITE_ENABLE}": "1" if site.get("enable", False) else "0",
                            "{#STRUCT_ID}": effective_device_id,  # 使用找到的device_id
                            "{#DEVICE_ID}": effective_device_id,  # 备用
                            "{#STRUCT_PK}": struct_pk  # 原始的struct_pk值，用于调试
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
    parser.add_argument('--debug', action='store_true', help='启用调试输出')
    
    args = parser.parse_args()
    
    # 创建发现客户端
    discovery = WAFSiteDiscovery(host=args.host, token=args.token)
    
    # 执行发现
    if args.type == 'sites':
        print(discovery.discover_sites(debug=args.debug))
    else:
        print(discovery.discover_devices())


if __name__ == "__main__":
    main()