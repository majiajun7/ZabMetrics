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
        尝试从集群拓扑中获取实际的设备ID
        
        :return: dict，key为app_id，value为实际的device_id
        """
        mapping = {}
        site_to_cluster = {}  # 站点ID到集群ID的映射
        
        try:
            # 首先获取设备信息
            device_info_url = f"{self.host}/api/v1/device/info/"
            response = requests.get(
                device_info_url,
                headers=self.headers,
                verify=False,
                timeout=10
            )
            
            device_serial = None
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    device_serial = data.get("data", {}).get("serial", "")
            
            # 尝试获取集群拓扑信息
            for site_type in ['transparent', 'reverse', 'traction', 'sniffer', 'bridge']:
                url = f"{self.host}/api/v1/website/tree/{site_type}/"
                response = requests.get(
                    url,
                    headers=self.headers,
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("code") == "SUCCESS":
                        tree_data = data.get("data", [])
                        
                        # 递归查找站点和它所属的集群
                        def find_sites_in_tree(nodes, parent_cluster=None):
                            for node in nodes:
                                node_type = node.get("struct_type")
                                node_id = node.get("_pk")
                                
                                if node_type == "cluster":
                                    parent_cluster = node_id
                                elif node_type == "site":
                                    # 记录站点ID到集群ID的映射
                                    site_to_cluster[node_id] = parent_cluster
                                
                                # 递归处理子节点
                                children = node.get("children", [])
                                if children:
                                    find_sites_in_tree(children, parent_cluster)
                        
                        find_sites_in_tree(tree_data)
            
            # 构建最终的映射关系
            for site_id, cluster_id in site_to_cluster.items():
                if cluster_id and cluster_id not in ["0", "1"]:
                    mapping[site_id] = cluster_id
                elif device_serial:
                    # 如果没有集群ID，使用设备序列号
                    mapping[site_id] = device_serial
                else:
                    mapping[site_id] = "0"  # 默认值
                    
        except Exception:
            pass
        
        return mapping
    
    def find_device_id_for_site(self, app_id):
        """
        为特定站点查找正确的device_id
        
        :param app_id: 站点ID
        :return: device_id (UUID格式) 或 None
        """
        # 遍历所有站点类型的拓扑树
        for site_type in ['transparent', 'reverse', 'traction', 'sniffer', 'bridge']:
            tree_url = f"{self.host}/api/v1/website/tree/{site_type}/"
            tree_response = requests.get(
                tree_url,
                headers=self.headers,
                verify=False,
                timeout=10
            )
            
            if tree_response.status_code == 200:
                tree_data = tree_response.json()
                if tree_data.get("code") == "SUCCESS":
                    tree_items = tree_data.get("data", [])
                    
                    # 递归查找包含该站点的集群
                    def find_cluster_for_site(nodes, parent_cluster=None):
                        for node in nodes:
                            if node.get("struct_type") == "cluster":
                                parent_cluster = node.get("_pk")
                            elif node.get("struct_type") == "site" and node.get("_pk") == app_id:
                                return parent_cluster
                            
                            # 递归查找子节点
                            children = node.get("children", [])
                            if children:
                                result = find_cluster_for_site(children, parent_cluster)
                                if result:
                                    return result
                        return None
                    
                    cluster_id = find_cluster_for_site(tree_items)
                    if cluster_id and cluster_id not in ["0", "1"]:
                        return cluster_id
        
        return None
    
    def discover_sites(self):
        """
        发现所有站点
        
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
                    print(f"发现 {len(sites)} 个站点，开始查找device_id...")
                    for site in sites:
                        site_id = site.get("_pk", "")
                        struct_pk = site.get("struct_pk", "")
                        
                        # 如果struct_pk是"0"（全局配置），需要查找实际的device_id
                        if struct_pk == "0":
                            actual_device_id = self.find_device_id_for_site(site_id)
                            if actual_device_id:
                                site_device_mapping[site_id] = actual_device_id
                                print(f"站点 {site.get('name')} ({site_id}) -> device_id: {actual_device_id}")
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
                                                        print(f"通过测试找到站点 {site.get('name')} 的device_id: {test_id}")
                                                        break
                                        except:
                                            pass
                        else:
                            # struct_pk不是"0"，直接使用
                            site_device_mapping[site_id] = struct_pk
                    
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
                            "{#DEVICE_ID}": effective_device_id   # 备用
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