#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
明御WAF流量数据采集脚本
用于Zabbix监控项数据采集
"""

import sys
import json
import time
import argparse
import requests
from datetime import datetime
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WAFTrafficCollector:
    def __init__(self, host, token):
        """
        初始化WAF监控客户端
        
        :param host: WAF管理地址
        :param token: API Token
        """
        self.host = host.rstrip('/')
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    
    def get_device_id(self):
        """
        获取设备ID
        
        :return: 设备ID
        """
        try:
            url = f"{self.host}/api/v1/device/info/"
            response = requests.get(
                url,
                headers=self.headers,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    # 使用设备序列号作为device_id
                    return data.get("data", {}).get("serial", "")
            
            return None
            
        except Exception:
            return None
    
    def get_traffic_data(self, app_id, device_id=None, debug=False):
        """
        获取指定站点的流量监控数据
        
        :param app_id: 站点ID
        :param device_id: 设备ID（可选）
        :param debug: 是否启用调试模式
        :return: 返回最新的流量数据
        """
        # 如果没有提供device_id，尝试自动获取
        if not device_id:
            device_id = self.get_device_id()
            if debug:
                print(f"自动获取的设备ID: {device_id}")
            if not device_id:
                # 如果无法获取设备ID，使用默认值
                device_id = "default"
                if debug:
                    print("无法获取设备ID，使用默认值: default")
        
        # 保存原始device_id
        original_device_id = device_id
        
        # 如果device_id是"auto"、"0"或空，需要自动发现
        if not device_id or device_id in ["0", "auto"]:
            if debug:
                print(f"device_id为'{device_id}'，需要自动发现实际的device_id...")
            # 直接调用查找方法，它会尝试多种方式找到正确的UUID格式的device_id
            actual_device_id = self._find_actual_device_id(app_id, debug)
            if actual_device_id:
                if debug:
                    print(f"找到有效的device_id: {actual_device_id}")
                device_id = actual_device_id
                original_device_id = actual_device_id
            else:
                # 如果还是找不到，尝试使用设备序列号
                device_serial = self.get_device_id()
                if device_serial:
                    if debug:
                        print(f"使用设备序列号作为备用: {device_serial}")
                    device_id = device_serial
                    original_device_id = device_serial
        
        # 定义一个内部函数来尝试获取数据
        def try_get_data(test_device_id):
            params = {
                "type": "mins",
                "app_id": app_id,
                "device_id": test_device_id,
                "_ts": int(time.time() * 1000)
            }
            
            if debug:
                print(f"尝试device_id: {test_device_id}")
                print(f"请求参数: {params}")
            
            try:
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
                        result = data.get("data", {}).get("result", [])
                        # 检查是否有有效数据（不全是"-"）
                        if result:
                            for record in result:
                                for key, value in record.items():
                                    if key != "timestamp" and value != "-":
                                        if debug:
                                            print(f"找到有效数据，使用device_id: {test_device_id}")
                                        return result
                        return result
            except Exception as e:
                if debug:
                    print(f"请求异常: {e}")
            return []
        
        url = f"{self.host}/api/v1/logs/traffic/"
        
        # 首先尝试使用原始device_id
        result = try_get_data(original_device_id)
        if result and any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
            return result
        
        # 如果原始device_id返回的都是"-"，尝试其他方式
        if original_device_id == "0" or not any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
            if debug:
                print("原始device_id未返回有效数据，尝试查找实际设备ID...")
            
            # 方法1：从站点信息中查找可能的device_id
            try:
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
                            if site.get("_pk") == app_id:
                                struct_pk = site.get("struct_pk", "")
                                if struct_pk and struct_pk != original_device_id:
                                    test_result = try_get_data(struct_pk)
                                    if test_result and any(v != "-" for record in test_result for k, v in record.items() if k != "timestamp"):
                                        return test_result
                                break
            except Exception:
                pass
            
            # 方法2：尝试从集群拓扑中查找
            try:
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
                            for item in tree_items:
                                for area in item.get("children", []):
                                    for cluster in area.get("children", []):
                                        cluster_id = cluster.get("_pk")
                                        if cluster_id and cluster_id not in ["0", "1", original_device_id]:
                                            test_result = try_get_data(cluster_id)
                                            if test_result and any(v != "-" for record in test_result for k, v in record.items() if k != "timestamp"):
                                                if debug:
                                                    print(f"成功使用集群ID: {cluster_id}")
                                                return test_result
            except Exception:
                pass
            
            # 方法3：如果还是没有找到，尝试使用获取的设备序列号
            device_serial = self.get_device_id()
            if device_serial and device_serial != original_device_id:
                if debug:
                    print(f"尝试使用设备序列号: {device_serial}")
                test_result = try_get_data(device_serial)
                if test_result and any(v != "-" for record in test_result for k, v in record.items() if k != "timestamp"):
                    return test_result
        
        # 返回最后的结果（可能都是"-"）
        return result
    
    def get_metric(self, app_id, metric_name, device_id=None):
        """
        获取指定站点和指标的最新值
        
        :param app_id: 站点ID
        :param metric_name: 指标名称
        :param device_id: 设备ID（可选）
        :return: 指标值
        """
        try:
            traffic_data = self.get_traffic_data(app_id, device_id)
            
            if not traffic_data:
                return 0
            
            # 返回最新的数据（第一条记录）
            # traffic_data已经按时间倒序排列，第一条就是最新的
            if traffic_data:
                latest_record = traffic_data[0]
                value = latest_record.get(metric_name, "-")
                # 如果值是"-"，返回0
                if value == "-":
                    return 0
                return value
            
            # 如果没有数据，返回0
            return 0
            
        except Exception as e:
            # 出错时返回0，避免Zabbix报错
            return 0
    
    def get_all_metrics(self, app_id, device_id=None):
        """
        获取指定站点的所有指标
        
        :param app_id: 站点ID
        :param device_id: 设备ID（可选）
        :return: JSON格式的所有指标数据
        """
        try:
            traffic_data = self.get_traffic_data(app_id, device_id)
            
            if not traffic_data:
                return json.dumps({
                    "status": "no_data",
                    "app_id": app_id,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
            
            # 查找最新的有效数据
            for record in traffic_data:
                # 检查是否是有效数据
                valid_data = False
                for key, value in record.items():
                    if key != "timestamp" and value != "-":
                        valid_data = True
                        break
                
                if valid_data:
                    # 构建返回数据
                    metrics = {}
                    for key, value in record.items():
                        if key != "timestamp":
                            metrics[key] = 0 if value == "-" else value
                    
                    metrics.update({
                        "status": "ok",
                        "app_id": app_id,
                        "data_timestamp": record.get("timestamp", ""),
                        "collect_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
                    return json.dumps(metrics, ensure_ascii=False)
            
            # 如果没有有效数据
            return json.dumps({
                "status": "all_empty",
                "app_id": app_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
        except Exception as e:
            return json.dumps({
                "status": "error",
                "app_id": app_id,
                "error": str(e),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
    
    def check_site_status(self, app_id):
        """
        检查站点状态
        
        :param app_id: 站点ID
        :return: 1表示正常，0表示异常
        """
        try:
            # 获取站点信息
            url = f"{self.host}/api/v1/website/site/"
            params = {
                "page": 1,
                "per_page": 1000
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
                    for site in sites:
                        if site.get("_pk") == app_id:
                            return 1 if site.get("enable", False) else 0
            
            return 0
            
        except Exception:
            return 0
    
    def _find_actual_device_id(self, app_id, debug=False):
        """
        查找站点实际使用的device_id
        使用 /api/v1/device/name/ 接口获取正确的device_id
        
        :param app_id: 站点ID
        :param debug: 是否启用调试模式
        :return: 实际的device_id或None
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
                            print(f"从device/name接口获取到device_id: {device_id}")
                        # 验证这个device_id是否能获取到流量数据
                        url = f"{self.host}/api/v1/logs/traffic/"
                        test_params = {
                            "type": "mins",
                            "app_id": app_id,
                            "device_id": device_id,
                            "_ts": int(time.time() * 1000)
                        }
                        test_response = requests.get(
                            url,
                            headers=self.headers,
                            params=test_params,
                            verify=False,
                            timeout=10
                        )
                        if test_response.status_code == 200:
                            test_data = test_response.json()
                            if test_data.get("code") == "SUCCESS":
                                result = test_data.get("data", {}).get("result", [])
                                if result and any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
                                    return device_id
                                elif debug:
                                    print(f"device_id {device_id} 返回的数据都是空的")
            
            # 如果上述方法失败，返回None
            if debug:
                print("无法从device/name接口获取有效的device_id")
            return None
            
        except Exception as e:
            if debug:
                print(f"查找device_id时出错: {e}")
            return None


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(description='明御WAF流量数据采集脚本')
    parser.add_argument('--host', required=True, help='WAF管理地址')
    parser.add_argument('--token', required=True, help='API Token')
    parser.add_argument('--app-id', required=True, help='站点ID')
    parser.add_argument('--device-id', help='设备ID（可选，会自动获取）')
    parser.add_argument('--metric', help='要获取的指标名称')
    parser.add_argument('--all', action='store_true', help='获取所有指标')
    parser.add_argument('--check', action='store_true', help='检查站点状态')
    parser.add_argument('--debug', action='store_true', help='调试模式')
    
    args = parser.parse_args()
    
    # 创建采集器
    collector = WAFTrafficCollector(host=args.host, token=args.token)
    
    # 执行相应的操作
    if args.check:
        # 检查站点状态
        status = collector.check_site_status(args.app_id)
        print(status)
    elif args.all:
        # 获取所有指标
        metrics = collector.get_all_metrics(args.app_id, args.device_id)
        print(metrics)
    elif args.metric:
        # 如果是调试模式，先打印原始数据
        if args.debug:
            traffic_data = collector.get_traffic_data(args.app_id, args.device_id, debug=True)
            print("---返回的流量数据---")
            print(json.dumps(traffic_data, indent=2, ensure_ascii=False))
            print("---")
        # 获取单个指标
        value = collector.get_metric(args.app_id, args.metric, args.device_id)
        print(value)
    else:
        parser.error("必须指定 --metric、--all 或 --check 参数之一")


if __name__ == "__main__":
    main()