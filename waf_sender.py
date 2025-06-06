#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAF流量数据采集器 - Zabbix Sender模式
使用Zabbix Sender批量发送数据，提高效率
完整实现所有监控项功能
"""

import os
import sys
import json
import time
import argparse
import logging
import requests
import urllib3
from subprocess import Popen, PIPE
import tempfile

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置日志 - 默认输出到stderr，避免干扰stdout的返回值
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr  # 重要：日志输出到stderr，不影响stdout
)
logger = logging.getLogger(__name__)

class WAFCollector:
    """WAF数据采集器"""
    
    def __init__(self, waf_host, token, zabbix_server, zabbix_host):
        """
        初始化采集器
        
        Args:
            waf_host: WAF管理地址
            token: API认证令牌
            zabbix_server: Zabbix服务器地址
            zabbix_host: Zabbix中的主机名
        """
        self.waf_host = waf_host.rstrip('/')
        self.token = token
        self.zabbix_server = zabbix_server
        self.zabbix_host = zabbix_host
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'
        })
        self.cached_sites = []  # 缓存站点信息
        self.cached_device_id = None  # 缓存设备ID
        
    def login(self):
        """验证连接（使用Bearer token已经在header中）"""
        # 由于我们使用Bearer token认证，不需要单独的登录步骤
        # 直接测试一个API来验证连接
        try:
            response = self.session.get(
                f"{self.waf_host}/api/v1/device/name/",
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("WAF连接验证成功")
                return True
            else:
                logger.error(f"WAF连接验证失败: HTTP {response.status_code}")
                logger.debug(f"响应内容: {response.text}")
                
        except Exception as e:
            logger.error(f"WAF连接异常: {e}")
            
        return False
        
    def get_device_id(self):
        """
        获取设备ID
        使用 /api/v1/device/name/ 接口获取正确的UUID格式device_id
        """
        # 如果已经缓存了设备ID，直接返回
        if self.cached_device_id:
            return self.cached_device_id
            
        try:
            # 从 /api/v1/device/name/ 接口获取设备ID
            response = self.session.get(
                f"{self.waf_host}/api/v1/device/name/",
                params={"_ts": int(time.time() * 1000)},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                logger.debug(f"设备响应数据: {data}")
                if data and data.get('code') == 'SUCCESS':
                    # 获取设备ID
                    device_info = data.get('data', {})
                    device_id = device_info.get('id')
                    if device_id:
                        logger.debug(f"获取到设备ID: {device_id}")
                        self.cached_device_id = device_id  # 缓存设备ID
                        return device_id
                                
        except Exception as e:
            logger.error(f"获取设备ID失败: {e}")
            
        return None
    
    def get_device_serial(self):
        """
        获取设备序列号作为备用device_id
        使用 /api/v1/device/info/ 接口（参考waf_traffic_collector.py）
        """
        try:
            response = self.session.get(
                f"{self.waf_host}/api/v1/device/info/",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    # 使用设备序列号作为device_id
                    return data.get("data", {}).get("serial", "")
            
            return None
            
        except Exception:
            return None
        
    def get_sites(self):
        """获取所有站点信息"""
        try:
            response = self.session.get(
                f"{self.waf_host}/api/v1/website/site/",
                params={
                    "page": 1,
                    "per_page": 1000,
                    "_ts": int(time.time() * 1000)
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                logger.debug(f"站点列表响应数据: {data}")
                sites = []
                
                if data.get("code") == "SUCCESS":
                    # 处理响应数据
                    items = data.get("data", {}).get("result", [])
                    for site in items:
                        site_obj = {
                            'id': site.get('_pk', ''),
                            'name': site.get('name', ''),
                            'enabled': site.get('enable', False),  # enable字段表示启用状态
                            'struct_id': site.get('struct_pk', '')  # struct_pk是关联的设备ID
                        }
                        sites.append(site_obj)
                    
                    logger.info(f"发现 {len(sites)} 个站点")
                    self.cached_sites = sites  # 缓存站点信息
                return sites
                    
        except Exception as e:
            logger.error(f"获取站点列表失败: {e}")
            
        return []
        
    def find_working_device_id(self, app_id, original_device_id):
        """
        智能查找可用的device_id
        整合了waf_traffic_collector.py的最佳实践
        """
        # 处理"0"、"auto"或空值的情况
        if not original_device_id or original_device_id in ["0", "auto"]:
            real_device_id = self.get_device_id()
            if real_device_id:
                logger.debug(f"站点 {app_id} 的device_id是'{original_device_id}'，使用真实设备ID: {real_device_id}")
                return real_device_id
        
        # 尝试使用流量API获取数据的辅助函数
        def try_get_data(test_device_id):
            params = {
                "type": "mins",
                "app_id": app_id,
                "device_id": test_device_id,
                "_ts": int(time.time() * 1000)
            }
            
            try:
                response = self.session.get(
                    f"{self.waf_host}/api/v1/logs/traffic/",
                    params=params,
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
                                        logger.debug(f"找到有效数据，使用device_id: {test_device_id}")
                                        return test_device_id, result
                        return test_device_id, result
            except Exception as e:
                logger.debug(f"尝试device_id {test_device_id} 失败: {e}")
            return None, []
        
        # 首先尝试原始device_id
        device_id, result = try_get_data(original_device_id)
        if result and any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
            return device_id
        
        # 如果原始device_id失败，尝试多种方法
        if not result or not any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
            logger.debug(f"原始device_id {original_device_id} 未返回有效数据，尝试其他方法...")
            
            # 方法1：从站点列表查找struct_pk
            try:
                for site in self.cached_sites:
                    if site.get('id') == app_id:
                        struct_pk = site.get('struct_id', '')
                        if struct_pk and struct_pk != original_device_id and struct_pk != "0":
                            device_id, result = try_get_data(struct_pk)
                            if result and any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
                                return device_id
                        break
            except Exception:
                pass
            
            # 方法2：尝试从设备名称接口获取UUID格式的device_id
            real_device_id = self.get_device_id()
            if real_device_id and real_device_id != original_device_id:
                device_id, result = try_get_data(real_device_id)
                if result and any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
                    return device_id
            
            # 方法3：如果还是没有找到，尝试从集群拓扑查找（参考waf_traffic_collector.py）
            try:
                for site_type in ['reverse', 'transparent', 'traction', 'sniffer', 'bridge']:
                    tree_url = f"{self.waf_host}/api/v1/website/tree/{site_type}/"
                    tree_response = self.session.get(tree_url, timeout=10)
                    if tree_response.status_code == 200:
                        tree_data = tree_response.json()
                        if tree_data.get("code") == "SUCCESS":
                            tree_items = tree_data.get("data", [])
                            for item in tree_items:
                                for area in item.get("children", []):
                                    for cluster in area.get("children", []):
                                        cluster_id = cluster.get("_pk")
                                        if cluster_id and cluster_id not in ["0", "1", original_device_id]:
                                            device_id, result = try_get_data(cluster_id)
                                            if result and any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
                                                logger.debug(f"成功使用集群ID: {cluster_id}")
                                                return device_id
            except Exception as e:
                logger.debug(f"集群拓扑查找失败: {e}")
            
            # 方法4：最后尝试使用设备序列号作为备用（参考waf_traffic_collector.py）
            device_serial = self.get_device_serial()
            if device_serial and device_serial != original_device_id:
                logger.debug(f"尝试使用设备序列号: {device_serial}")
                device_id, result = try_get_data(device_serial)
                if result and any(v != "-" for record in result for k, v in record.items() if k != "timestamp"):
                    return device_id
            
        return original_device_id
    
    def get_traffic_data(self, app_id, device_id):
        """获取站点流量数据"""
        try:
            # 智能查找有效的device_id
            working_device_id = self.find_working_device_id(app_id, device_id)
            
            # 使用找到的device_id获取数据
            params = {
                "type": "mins",
                "app_id": app_id,
                "device_id": working_device_id,
                "_ts": int(time.time() * 1000)
            }
            
            response = self.session.get(
                f"{self.waf_host}/api/v1/logs/traffic/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("code") == "SUCCESS":
                    results = data.get("data", {}).get("result", [])
                    if results and len(results) > 0:
                        # 获取最新的有效数据点（第一条记录是最新的）
                        for record in results:
                            # 检查是否有有效数据
                            valid_data = False
                            for key, value in record.items():
                                if key != "timestamp" and value != "-":
                                    valid_data = True
                                    break
                            
                            if valid_data:
                                # 处理数据，将"-"转换为0，使用正确的字段名
                                return {
                                    'bytesInRateAvg': float(record.get('bytes_in_rate_avg', 0)) if record.get('bytes_in_rate_avg') != '-' else 0,
                                    'bytesInRateMax': float(record.get('bytes_in_rate_max', 0)) if record.get('bytes_in_rate_max') != '-' else 0,
                                    'bytesOutRateAvg': float(record.get('bytes_out_rate_avg', 0)) if record.get('bytes_out_rate_avg') != '-' else 0,
                                    'bytesOutRateMax': float(record.get('bytes_out_rate_max', 0)) if record.get('bytes_out_rate_max') != '-' else 0,
                                    'connCurAvg': float(record.get('conn_cur_avg', 0)) if record.get('conn_cur_avg') != '-' else 0,
                                    'connCurMax': float(record.get('conn_cur_max', 0)) if record.get('conn_cur_max') != '-' else 0,
                                    'connRateAvg': float(record.get('conn_rate_avg', 0)) if record.get('conn_rate_avg') != '-' else 0,
                                    'httpReqCntAvg': float(record.get('http_req_cnt_avg', 0)) if record.get('http_req_cnt_avg') != '-' else 0,
                                    'httpReqCntMax': float(record.get('http_req_cnt_max', 0)) if record.get('http_req_cnt_max') != '-' else 0,
                                    'httpReqRateAvg': float(record.get('http_req_rate_avg', 0)) if record.get('http_req_rate_avg') != '-' else 0
                                }
                else:
                    logger.debug(f"流量API返回错误: {data}")
                    
        except Exception as e:
            logger.debug(f"获取流量数据失败 (app_id={app_id}): {e}")
            
        # 返回全零数据，避免监控项无数据
        return {
            'bytesInRateAvg': 0,
            'bytesInRateMax': 0,
            'bytesOutRateAvg': 0,
            'bytesOutRateMax': 0,
            'connCurAvg': 0,
            'connCurMax': 0,
            'connRateAvg': 0,
            'httpReqCntAvg': 0,
            'httpReqCntMax': 0,
            'httpReqRateAvg': 0
        }
        
    def collect_all_data(self):
        """收集所有站点的数据"""
        # 登录
        if not self.login():
            logger.error("无法登录WAF")
            return []
            
        # 获取设备ID
        device_id = self.get_device_id()
        if not device_id:
            logger.warning("无法获取设备ID，尝试使用默认值")
            device_id = "default"
            
        # 获取站点列表
        sites = self.get_sites()
        if not sites:
            logger.warning("未发现任何站点")
            return []
            
        # 收集数据
        all_data = []
        timestamp = int(time.time())
        
        # 添加采集器状态监控项
        all_data.append({
            'host': self.zabbix_host,
            'key': 'waf.collector.status',
            'value': 1,  # 1表示正常
            'clock': timestamp
        })
        
        # 添加采集器时间戳监控项
        all_data.append({
            'host': self.zabbix_host,
            'key': 'waf.collector.timestamp',
            'value': timestamp,
            'clock': timestamp
        })
        
        # 首先发送站点发现数据
        discovery_data = []
        for site in sites:
            # 确定每个站点的有效device_id
            site_device_id = site.get('struct_id', device_id)
            if site_device_id == '0' or not site_device_id:
                site_device_id = device_id
                
            discovery_data.append({
                "{#SITE_ID}": site['id'],
                "{#SITE_NAME}": site['name'],
                "{#SITE_TYPE}": "WAF",
                "{#SITE_IP}": "",
                "{#SITE_PORT}": "",
                "{#SITE_DOMAIN}": "",
                "{#SITE_ENABLE}": "1" if site['enabled'] else "0",
                "{#STRUCT_ID}": site_device_id,
                "{#DEVICE_ID}": site_device_id,
                "{#STRUCT_PK}": site.get('struct_id', '')
            })
            
        # 添加LLD数据
        all_data.append({
            'host': self.zabbix_host,
            'key': 'waf.sites.discovery',
            'value': json.dumps({"data": discovery_data}, ensure_ascii=False),
            'clock': timestamp
        })
        
        # 收集每个站点的流量数据
        for site in sites:
            site_name = site['name']
            
            # 站点状态
            all_data.append({
                'host': self.zabbix_host,
                'key': f'waf.site.status[{site_name}]',
                'value': 1 if site['enabled'] else 0,
                'clock': timestamp
            })
            
            # 获取流量数据
            if site['enabled']:
                # 如果struct_id是"0"，使用实际的device_id
                actual_device_id = device_id if site['struct_id'] == '0' else site['struct_id']
                traffic_data = self.get_traffic_data(site['id'], actual_device_id)
                
                # 入站流量
                bytes_in_avg = traffic_data.get('bytesInRateAvg', 0)
                bytes_in_max = traffic_data.get('bytesInRateMax', 0)
                all_data.extend([
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.bytes_in_rate_avg[{site_name}]',
                        'value': bytes_in_avg,  # 已经是bps，无需转换
                        'clock': timestamp
                    },
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.bytes_in_rate_max[{site_name}]',
                        'value': bytes_in_max,
                        'clock': timestamp
                    }
                ])
                
                # 出站流量
                bytes_out_avg = traffic_data.get('bytesOutRateAvg', 0)
                bytes_out_max = traffic_data.get('bytesOutRateMax', 0)
                all_data.extend([
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.bytes_out_rate_avg[{site_name}]',
                        'value': bytes_out_avg,
                        'clock': timestamp
                    },
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.bytes_out_rate_max[{site_name}]',
                        'value': bytes_out_max,
                        'clock': timestamp
                    }
                ])
                
                # 连接数
                conn_cur_avg = traffic_data.get('connCurAvg', 0)
                conn_cur_max = traffic_data.get('connCurMax', 0)
                conn_rate_avg = traffic_data.get('connRateAvg', 0)
                all_data.extend([
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.conn_cur_avg[{site_name}]',
                        'value': conn_cur_avg,
                        'clock': timestamp
                    },
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.conn_cur_max[{site_name}]',
                        'value': conn_cur_max,
                        'clock': timestamp
                    },
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.conn_rate_avg[{site_name}]',
                        'value': conn_rate_avg,
                        'clock': timestamp
                    }
                ])
                
                # HTTP请求
                http_req_cnt_avg = traffic_data.get('httpReqCntAvg', 0)
                http_req_cnt_max = traffic_data.get('httpReqCntMax', 0)
                http_req_rate_avg = traffic_data.get('httpReqRateAvg', 0)
                all_data.extend([
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.http_req_cnt_avg[{site_name}]',
                        'value': http_req_cnt_avg,
                        'clock': timestamp
                    },
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.http_req_cnt_max[{site_name}]',
                        'value': http_req_cnt_max,
                        'clock': timestamp
                    },
                    {
                        'host': self.zabbix_host,
                        'key': f'waf.site.http_req_rate_avg[{site_name}]',
                        'value': http_req_rate_avg,
                        'clock': timestamp
                    }
                ])
            else:
                # 站点禁用时，发送0值
                all_data.extend([
                    {'host': self.zabbix_host, 'key': f'waf.site.bytes_in_rate_avg[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.bytes_in_rate_max[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.bytes_out_rate_avg[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.bytes_out_rate_max[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.conn_cur_avg[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.conn_cur_max[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.conn_rate_avg[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.http_req_cnt_avg[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.http_req_cnt_max[{site_name}]', 'value': 0, 'clock': timestamp},
                    {'host': self.zabbix_host, 'key': f'waf.site.http_req_rate_avg[{site_name}]', 'value': 0, 'clock': timestamp}
                ])
                    
        return all_data
        
    def send_to_zabbix(self, data):
        """发送数据到Zabbix"""
        if not data:
            logger.warning("没有数据需要发送")
            return False
            
        try:
            # 创建临时文件，使用zabbix_sender的文本格式
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for item in data:
                    # 对包含空格或特殊字符的key和value进行引号包装
                    host = item["host"]
                    key = item["key"]
                    clock = item.get("clock", "")
                    value = item["value"]
                    
                    # 如果key包含空格或特殊字符，需要用引号包装
                    if ' ' in key or '[' in key:
                        key = f'"{key}"'
                    
                    # 如果value是字符串且包含空格或特殊字符，需要用引号包装
                    if isinstance(value, str) and (' ' in value or '"' in value or '\n' in value):
                        # 转义内部的引号
                        value = value.replace('\\', '\\\\').replace('"', '\\"')
                        value = f'"{value}"'
                    
                    # 格式: hostname key timestamp value
                    line = f'{host} {key} {clock} {value}\n'
                    f.write(line)
                temp_file = f.name
                
            logger.debug(f"临时文件路径: {temp_file}")
            logger.debug(f"发送数据样例: {json.dumps(data[:2], ensure_ascii=False)}")
            
            # 输出文件内容以便调试
            with open(temp_file, 'r') as f:
                content = f.read()
                logger.debug(f"临时文件前500字符:\n{content[:500]}")
                
            try:
                # 检查zabbix_sender是否存在
                import shutil
                zabbix_sender_path = shutil.which('zabbix_sender')
                if not zabbix_sender_path:
                    logger.error("zabbix_sender命令未找到，请先安装zabbix-sender")
                    return False
                    
                logger.debug(f"使用zabbix_sender: {zabbix_sender_path}")
                
                # 使用zabbix_sender发送
                cmd = [
                    zabbix_sender_path,
                    '-z', self.zabbix_server,
                    '-i', temp_file,
                    '-vv',  # 增加详细输出
                    '-T'    # 打印失败的监控项
                ]
                
                logger.debug(f"执行命令: {' '.join(cmd)}")
                
                process = Popen(cmd, stdout=PIPE, stderr=PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    logger.info(f"成功发送 {len(data)} 个数据项到Zabbix")
                    if stdout:
                        logger.debug(f"Zabbix sender输出: {stdout.decode()}")
                    return True
                else:
                    logger.error(f"Zabbix sender失败: {stderr.decode()}")
                    if stdout:
                        logger.error(f"标准输出: {stdout.decode()}")
                    return False
                    
            finally:
                # 删除临时文件
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    
        except Exception as e:
            logger.error(f"发送数据到Zabbix失败: {e}")
            return False
            
    def run(self):
        """运行采集器"""
        logger.info("开始采集WAF数据...")
        
        try:
            # 收集数据
            data = self.collect_all_data()
            
            if data:
                logger.info(f"收集到 {len(data)} 个数据项")
                
                # 发送到Zabbix
                if self.send_to_zabbix(data):
                    logger.info("数据发送成功")
                    return True
                else:
                    logger.error("数据发送失败")
                    # 发送失败时，仍然尝试发送采集器状态
                    self.send_collector_status(0)
                    return False
            else:
                logger.warning("未收集到任何数据")
                # 无数据时，发送采集器状态为异常
                self.send_collector_status(0)
                return False
        except Exception as e:
            logger.error(f"采集过程出错: {e}")
            # 出错时，发送采集器状态为异常
            self.send_collector_status(0)
            return False
    
    def send_collector_status(self, status):
        """发送采集器状态"""
        try:
            timestamp = int(time.time())
            status_data = [
                {
                    'host': self.zabbix_host,
                    'key': 'waf.collector.status',
                    'value': status,
                    'clock': timestamp
                }
            ]
            self.send_to_zabbix(status_data)
        except Exception as e:
            logger.error(f"发送采集器状态失败: {e}")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='WAF流量数据采集器 - Zabbix Sender模式')
    parser.add_argument('--waf-host', required=True, help='WAF管理地址')
    parser.add_argument('--token', required=True, help='API认证令牌')
    parser.add_argument('--zabbix-server', required=True, help='Zabbix服务器地址')
    parser.add_argument('--zabbix-host', required=True, help='Zabbix中的主机名')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    parser.add_argument('--quiet', action='store_true', help='静默模式，不输出日志')
    
    args = parser.parse_args()
    
    # 配置日志
    if args.quiet:
        # 静默模式：禁用所有日志输出
        logging.getLogger().setLevel(logging.CRITICAL + 1)
    else:
        # 设置日志级别
        logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)
        
    # 创建采集器并运行
    collector = WAFCollector(
        args.waf_host,
        args.token,
        args.zabbix_server,
        args.zabbix_host
    )
    
    # 执行数据采集
    success = collector.run()
    
    # 输出结果：0表示成功，1表示失败（符合Zabbix外部检查的期望）
    print(0 if success else 1)
    
    # 仍然使用sys.exit返回正确的退出码
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()