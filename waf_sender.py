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
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'
        })
        
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
        """获取设备ID"""
        try:
            # 先尝试从设备列表获取
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
                        return device_id
                                
        except Exception as e:
            logger.error(f"获取设备ID失败: {e}")
            
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
                return sites
                    
        except Exception as e:
            logger.error(f"获取站点列表失败: {e}")
            
        return []
        
    def get_traffic_data(self, app_id, device_id):
        """获取站点流量数据"""
        try:
            # 使用流量日志API
            params = {
                '_ts': int(time.time() * 1000),
                'site_struct_pk': device_id,
                'site_pk': app_id,
                'offset': 0,
                'limit': 1,
                'start': int(time.time() - 300) * 1000,  # 5分钟前
                'end': int(time.time()) * 1000
            }
            
            response = self.session.get(
                f"{self.waf_host}/api/v1/logs/traffic/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                logger.debug(f"流量数据响应: {data}")
                
                if data.get("code") == "SUCCESS":
                    results = data.get("data", {}).get("result", [])
                    if results and len(results) > 0:
                        # 获取最新的数据点
                        latest = results[-1] if isinstance(results, list) else results
                        return {
                            'bytesInRateAvg': latest.get('bytes_in_rate', 0),
                            'bytesInRateMax': latest.get('bytes_in_rate', 0),
                            'bytesOutRateAvg': latest.get('bytes_out_rate', 0),
                            'bytesOutRateMax': latest.get('bytes_out_rate', 0),
                            'connCurAvg': latest.get('conn_cur', 0),
                            'connCurMax': latest.get('conn_cur', 0),
                            'connRateAvg': latest.get('conn_rate', 0),
                            'httpReqCntAvg': latest.get('http_req_cnt', 0),
                            'httpReqCntMax': latest.get('http_req_cnt', 0),
                            'httpReqRateAvg': latest.get('http_req_rate', 0)
                        }
                else:
                    logger.debug(f"流量API返回错误: {data}")
                    
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
            
            # 暂时跳过流量数据获取，先测试基本功能
            # TODO: 修复流量API调用后再启用
            pass
                    
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