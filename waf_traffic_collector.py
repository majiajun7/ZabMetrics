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
    
    def get_traffic_data(self, app_id, device_id=None):
        """
        获取指定站点的流量监控数据
        
        :param app_id: 站点ID
        :param device_id: 设备ID（可选）
        :return: 返回最新的流量数据
        """
        # 如果没有提供device_id，尝试自动获取
        if not device_id:
            device_id = self.get_device_id()
            if not device_id:
                # 如果无法获取设备ID，使用默认值
                device_id = "default"
        
        url = f"{self.host}/api/v1/logs/traffic/"
        params = {
            "type": "mins",
            "app_id": app_id,
            "device_id": device_id,
            "_ts": int(time.time() * 1000)
        }
        
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
                    return data.get("data", {}).get("result", [])
                else:
                    # 某些站点可能没有流量数据
                    return []
            else:
                return []
                
        except Exception:
            return []
    
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
            
            # 查找最新的有效数据（非"-"的数据）
            for record in traffic_data:
                value = record.get(metric_name, "-")
                if value != "-":
                    return value
            
            # 如果所有数据都是"-"，返回0
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
        # 获取单个指标
        value = collector.get_metric(args.app_id, args.metric, args.device_id)
        print(value)
    else:
        parser.error("必须指定 --metric、--all 或 --check 参数之一")


if __name__ == "__main__":
    main()