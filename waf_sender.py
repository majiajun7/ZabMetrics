#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAF流量数据采集器 - Zabbix Sender模式
使用Zabbix Sender批量发送数据，提高效率
"""

import os
import sys
import json
import time
import argparse
import logging
import requests
import urllib3
from datetime import datetime
from subprocess import Popen, PIPE, DEVNULL
import tempfile

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
            'Content-Type': 'application/json'
        })
        
    def login(self):
        """登录WAF获取session"""
        try:
            login_data = {"authToken": self.token}
            response = self.session.post(
                f"{self.waf_host}/api/open/auth",
                json=login_data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 0:
                    logger.info("WAF登录成功")
                    return True
                else:
                    logger.error(f"WAF登录失败: {result.get('message', '未知错误')}")
            else:
                logger.error(f"WAF登录请求失败: HTTP {response.status_code}")
                
        except Exception as e:
            logger.error(f"WAF登录异常: {e}")
            
        return False
        
    def get_device_id(self):
        """获取设备ID"""
        try:
            # 先尝试从设备列表获取
            response = self.session.get(
                f"{self.waf_host}/api/open/device/list",
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 0 and result.get('data'):
                    devices = result['data']
                    if devices:
                        # 获取第一个设备的ID
                        device_id = devices[0].get('clusterNodeId')
                        if device_id:
                            logger.debug(f"从设备列表获取到设备ID: {device_id}")
                            return device_id
                            
            # 尝试从集群拓扑获取
            response = self.session.get(
                f"{self.waf_host}/api/open/cluster/topology",
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 0 and result.get('data'):
                    # 查找本机或主设备
                    for node in result['data']:
                        if node.get('isLocal') or node.get('isMaster'):
                            device_id = node.get('nodeId')
                            if device_id:
                                logger.debug(f"从集群拓扑获取到设备ID: {device_id}")
                                return device_id
                                
        except Exception as e:
            logger.error(f"获取设备ID失败: {e}")
            
        return None
        
    def get_sites(self):
        """获取所有站点信息"""
        try:
            response = self.session.get(
                f"{self.waf_host}/api/open/application/list",
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 0:
                    sites = []
                    for app in result.get('data', []):
                        site = {
                            'id': app.get('id'),
                            'name': app.get('name'),
                            'enabled': app.get('enabled', False),
                            'struct_id': app.get('structId')
                        }
                        sites.append(site)
                    return sites
                    
        except Exception as e:
            logger.error(f"获取站点列表失败: {e}")
            
        return []
        
    def get_traffic_data(self, app_id, device_id):
        """获取站点流量数据"""
        try:
            now = int(time.time())
            start_time = now - 300  # 5分钟前
            
            params = {
                'clusterNodeId': device_id,
                'appId': app_id,
                'startTime': start_time,
                'endTime': now,
                'statistic': 'avg,max'
            }
            
            response = self.session.get(
                f"{self.waf_host}/api/open/traffic/app",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 0:
                    return result.get('data', {})
                    
        except Exception as e:
            logger.error(f"获取流量数据失败 (app_id={app_id}): {e}")
            
        return {}
        
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
        
        # 首先发送站点发现数据
        discovery_data = []
        for site in sites:
            discovery_data.append({
                "{#SITE_ID}": site['id'],
                "{#SITE_NAME}": site['name'],
                "{#STRUCT_ID}": site.get('struct_id', device_id)
            })
            
        # 添加LLD数据
        all_data.append({
            'host': self.zabbix_host,
            'key': 'waf.sites.discovery',
            'value': json.dumps({"data": discovery_data}),
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
                traffic_data = self.get_traffic_data(site['id'], device_id)
                
                if traffic_data:
                    # 入站流量
                    bytes_in_avg = traffic_data.get('bytesInRateAvg', 0)
                    bytes_in_max = traffic_data.get('bytesInRateMax', 0)
                    all_data.extend([
                        {
                            'host': self.zabbix_host,
                            'key': f'waf.site.bytes_in_rate_avg[{site_name}]',
                            'value': bytes_in_avg * 8,  # 转换为bps
                            'clock': timestamp
                        },
                        {
                            'host': self.zabbix_host,
                            'key': f'waf.site.bytes_in_rate_max[{site_name}]',
                            'value': bytes_in_max * 8,
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
                            'value': bytes_out_avg * 8,
                            'clock': timestamp
                        },
                        {
                            'host': self.zabbix_host,
                            'key': f'waf.site.bytes_out_rate_max[{site_name}]',
                            'value': bytes_out_max * 8,
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
                    
        return all_data
        
    def send_to_zabbix(self, data):
        """发送数据到Zabbix"""
        if not data:
            logger.warning("没有数据需要发送")
            return False
            
        try:
            # 准备发送数据
            send_data = {
                "request": "sender data",
                "data": data
            }
            
            # 创建临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(send_data, f)
                temp_file = f.name
                
            try:
                # 使用zabbix_sender发送
                cmd = [
                    'zabbix_sender',
                    '-z', self.zabbix_server,
                    '-i', temp_file
                ]
                
                process = Popen(cmd, stdout=PIPE, stderr=PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    logger.info(f"成功发送 {len(data)} 个数据项到Zabbix")
                    if stdout:
                        logger.debug(f"Zabbix sender输出: {stdout.decode()}")
                    return True
                else:
                    logger.error(f"Zabbix sender失败: {stderr.decode()}")
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
                return False
        else:
            logger.warning("未收集到任何数据")
            return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='WAF流量数据采集器 - Zabbix Sender模式')
    parser.add_argument('--waf-host', required=True, help='WAF管理地址')
    parser.add_argument('--token', required=True, help='API认证令牌')
    parser.add_argument('--zabbix-server', required=True, help='Zabbix服务器地址')
    parser.add_argument('--zabbix-host', required=True, help='Zabbix中的主机名')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # 创建采集器并运行
    collector = WAFCollector(
        args.waf_host,
        args.token,
        args.zabbix_server,
        args.zabbix_host
    )
    
    if collector.run():
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()