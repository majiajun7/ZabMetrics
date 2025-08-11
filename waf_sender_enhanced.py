#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAF流量数据采集器 - 增强版
支持中心机模式、多集群、多域名监控
完整集成自动发现和数据采集功能
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
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)


class WAFCenterCollector:
    """WAF中心机数据采集器 - 支持多集群多域名"""
    
    def __init__(self, waf_host: str, token: str, zabbix_server: str, 
                 zabbix_host: str, data_type: str = 'mins'):
        """
        初始化采集器
        
        Args:
            waf_host: WAF管理地址
            token: API认证令牌
            zabbix_server: Zabbix服务器地址
            zabbix_host: Zabbix中的主机名
            data_type: 数据粒度类型 (mins/hours/days)
        """
        self.waf_host = waf_host.rstrip('/')
        self.token = token
        self.zabbix_server = zabbix_server
        self.zabbix_host = zabbix_host
        self.data_type = data_type
        
        # HTTP会话配置
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'
        })
        
        # 缓存
        self.cached_sites = []
        self.cached_clusters = {}
        self.cached_nodes = {}  # 节点信息缓存
        self.cached_device_id = None
        self.deployment_mode = "center"  # 只支持中心机模式
        
        # 运行时间记录文件
        self.last_run_file = os.path.join(
            '/tmp', 
            f'waf_sender_last_run_{self.zabbix_host.replace("/", "_")}.json'
        )
    
    def detect_deployment_mode(self) -> str:
        """
        返回中心机模式（唯一支持的模式）
        
        Returns:
            'center'
        """
        # 直接返回中心机模式，不再检测
        logger.info("使用中心机部署模式")
        self.deployment_mode = "center"
        return "center"
    
    def get_nodes_v2(self) -> Dict[str, Any]:
        """
        获取节点信息 - 使用v2 API
        
        Returns:
            节点信息字典，包含层级结构
        """
        if self.cached_nodes:
            return self.cached_nodes
        
        try:
            # 尝试v2 API
            response = self.session.get(
                f"{self.waf_host}/api/v2/umc/structs/nodes/",
                params={"_ts": int(time.time() * 1000)},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    structs = data.get("data", [])
                    
                    # 构建层级结构
                    areas = {}
                    clusters = {}
                    node_list = {}
                    
                    for struct in structs:
                        struct_type = struct.get('struct_type', '')
                        pk = struct.get('_pk', '')
                        name = struct.get('name', '')
                        
                        if struct_type == 'area':
                            areas[pk] = {
                                'id': pk,
                                'name': name,
                                'type': 'area'
                            }
                        elif struct_type == 'cluster':
                            clusters[pk] = {
                                'id': pk,
                                'name': name,
                                'area_id': struct.get('super_pk', ''),
                                'deploy': struct.get('deploy', ''),
                                'type': 'cluster'
                            }
                        elif struct_type == 'node':
                            node_list[pk] = {
                                'id': pk,
                                'name': name,
                                'ip': struct.get('ip', ''),
                                'cluster_id': struct.get('super_pk', ''),
                                'type': 'node'
                            }
                    
                    # 关联区域信息到集群
                    for cluster_id, cluster in clusters.items():
                        area_id = cluster['area_id']
                        if area_id in areas:
                            cluster['area_name'] = areas[area_id]['name']
                        else:
                            cluster['area_name'] = '默认区域'
                    
                    # 关联集群信息到节点
                    for node_id, node in node_list.items():
                        cluster_id = node['cluster_id']
                        if cluster_id in clusters:
                            node['cluster_name'] = clusters[cluster_id]['name']
                            node['area_name'] = clusters[cluster_id].get('area_name', '')
                        else:
                            node['cluster_name'] = '默认集群'
                            node['area_name'] = '默认区域'
                    
                    self.cached_nodes = {
                        'areas': areas,
                        'clusters': clusters,
                        'nodes': node_list
                    }
                    
                    logger.info(f"从v2 API获取到 {len(areas)} 个区域, {len(clusters)} 个集群, {len(node_list)} 个节点")
                    return self.cached_nodes
            
        except Exception as e:
            logger.error(f"获取v2节点信息失败: {e}")
        
        # 如果v2 API失败，返回空结构
        self.cached_nodes = {
            'areas': {},
            'clusters': {},
            'nodes': {}
        }
        return self.cached_nodes
    
    def get_clusters(self) -> Dict[str, Any]:
        """
        获取集群信息 - 优先使用v2 API，否则从站点数据中提取
        
        Returns:
            集群信息字典
        """
        if self.cached_clusters:
            return self.cached_clusters
        
        # 首先尝试从v2 API获取
        nodes_info = self.get_nodes_v2()
        if nodes_info and nodes_info.get('clusters'):
            self.cached_clusters = nodes_info['clusters']
            return self.cached_clusters
            
        clusters = {}
        
        # 如果v2 API失败，从站点数据中提取集群信息
        logger.info("从站点数据中提取集群信息（v2 API不可用）")
        
        try:
            # 获取所有站点
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
                if data.get("code") == "SUCCESS":
                    sites = data.get("data", {}).get("result", [])
                    
                    # 从站点数据中提取唯一的集群信息
                    for site in sites:
                        struct_pk = site.get('struct_pk', '')
                        if struct_pk and struct_pk not in ["0", "1", ""]:
                            if struct_pk not in clusters:
                                # 创建虚拟的集群信息
                                clusters[struct_pk] = {
                                    "id": struct_pk,
                                    "name": f"集群-{struct_pk[:8]}",  # 使用ID前8位作为名称
                                    "area": "默认区域",
                                    "type": site.get('type', 'unknown'),
                                    "site_count": 0
                                }
                            clusters[struct_pk]["site_count"] += 1
            
            logger.info(f"从站点数据中发现 {len(clusters)} 个集群")
            self.cached_clusters = clusters
            
        except Exception as e:
            logger.error(f"从站点数据提取集群信息失败: {e}")
            
        return clusters
    
    def get_device_id(self) -> Optional[str]:
        """获取设备ID - 尝试多个API端点"""
        if self.cached_device_id:
            return self.cached_device_id
        
        # 尝试多个可能的API端点
        api_endpoints = [
            "/api/v1/device/name/",
            "/api/v1/device/info/",
            "/api/v1/device/hardware/info/"
        ]
        
        for endpoint in api_endpoints:
            try:
                logger.debug(f"尝试获取设备ID，使用端点: {endpoint}")
                response = self.session.get(
                    f"{self.waf_host}{endpoint}",
                    params={"_ts": int(time.time() * 1000)},
                    timeout=30
                )
                
                logger.debug(f"设备API请求URL: {response.url}")
                logger.debug(f"设备API响应状态: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    logger.debug(f"设备API原始响应 ({endpoint}): {json.dumps(data, ensure_ascii=False, indent=2)}")
                    
                    if data.get('code') == 'SUCCESS':
                        device_info = data.get('data', {})
                        # 尝试不同的字段名
                        device_id = device_info.get('id') or device_info.get('device_id') or device_info.get('serial')
                        if device_id:
                            logger.info(f"从 {endpoint} 获取到设备ID: {device_id}")
                            self.cached_device_id = device_id
                            return device_id
                        else:
                            logger.warning(f"设备API ({endpoint}) 返回的data中没有找到ID字段: {device_info}")
                    else:
                        logger.warning(f"设备API ({endpoint}) 返回失败: {data}")
                            
            except Exception as e:
                logger.error(f"从 {endpoint} 获取设备ID失败: {e}")
        
        logger.error("所有设备API端点都无法获取设备ID")
        return None
    
    def get_sites_by_node_v2(self, node_id: str) -> List[Dict]:
        """
        获取指定节点的站点信息 - 使用v2 API
        
        Args:
            node_id: 节点ID
            
        Returns:
            站点列表
        """
        sites_list = []
        
        try:
            # 使用v2 API获取节点站点
            response = self.session.get(
                f"{self.waf_host}/api/v2/website/app_list/",
                params={
                    "simple": "true",
                    "namespace_id": node_id,
                    "_ts": int(time.time() * 1000)
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    sites = data.get("data", [])
                    for site in sites:
                        sites_list.append({
                            'id': site.get('_pk', ''),
                            'name': site.get('name', ''),
                            'type': site.get('type', ''),
                            'domains': site.get('domain', []),
                            'node_id': node_id,
                            'generic_profile': site.get('generic_profile', '')
                        })
                    logger.debug(f"节点 {node_id} 发现 {len(sites)} 个站点")
            
        except Exception as e:
            logger.error(f"获取节点 {node_id} 的站点失败: {e}")
            
        return sites_list
    
    def get_sites_with_domains(self) -> List[Dict]:
        """
        获取所有站点信息 - 支持按节点查询
        
        Returns:
            站点列表
        """
        sites_list = []
        
        # 先获取节点信息
        nodes_info = self.get_nodes_v2()
        
        # 如果有节点信息，按节点查询站点
        if nodes_info and nodes_info.get('nodes'):
            logger.info("使用v2 API按节点查询站点")
            
            # 为每个节点查询站点
            for node_id, node_info in nodes_info['nodes'].items():
                node_sites = self.get_sites_by_node_v2(node_id)
                
                for site in node_sites:
                    # 补充节点信息
                    site['node_name'] = node_info['name']
                    site['node_ip'] = node_info['ip']
                    site['cluster_id'] = node_info['cluster_id']
                    site['cluster_name'] = node_info.get('cluster_name', '')
                    site['area_name'] = node_info.get('area_name', '')
                    sites_list.append(site)
            
            logger.info(f"通过v2 API从所有节点共发现 {len(sites_list)} 个站点")
            
        # 如果v2 API失败或没有节点，回退到v1 API
        if not sites_list:
            logger.info("回退到v1 API获取站点")
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
                    if data.get("code") == "SUCCESS":
                        sites = data.get("data", {}).get("result", [])
                        
                        for site in sites:
                            site_id = site.get('_pk', '')
                            site_name = site.get('name', '')
                            struct_pk = site.get('struct_pk', '')
                            domains = site.get('domain', [])
                            
                            # 如果没有配置域名，使用通配符
                            if not domains:
                                domains = ['*']
                            
                            # 确定有效的device_id
                            if struct_pk == "0" or not struct_pk:
                                # 全局站点，使用中心机device_id
                                effective_device_id = self.get_device_id()
                                if not effective_device_id:
                                    # 如果获取不到设备ID，使用默认值
                                    effective_device_id = self.zabbix_host
                                    logger.warning(f"无法获取设备ID，使用Zabbix主机名: {effective_device_id}")
                                cluster_info = None
                                node_name = "中心机"
                            else:
                                # 集群站点，使用struct_pk作为device_id
                                effective_device_id = struct_pk
                                cluster_info = self.cached_clusters.get(struct_pk)
                                node_name = cluster_info['name'] if cluster_info else f"集群-{struct_pk[:8]}"
                            
                            # 创建站点监控项
                            site_item = {
                                'id': site_id,
                                'name': site_name,
                                'enabled': site.get('enable', False),
                                'type': site.get('type', ''),
                                'ip_set': site.get('ip_set', ''),
                                'port': site.get('port', []),
                                'domains': domains,
                                'struct_pk': struct_pk,
                                'device_id': effective_device_id,
                                'cluster_info': cluster_info,
                                'node_id': effective_device_id,
                                'node_name': node_name,
                                'cluster_id': struct_pk if struct_pk != "0" else "",
                                'cluster_name': cluster_info['name'] if cluster_info else "",
                                'area_name': cluster_info.get('area_name', '') if cluster_info else ""
                            }
                            sites_list.append(site_item)
                        
                        logger.info(f"通过v1 API发现 {len(sites)} 个站点")
                        
            except Exception as e:
                logger.error(f"获取站点列表失败: {e}")
            
        return sites_list
    
    def get_traffic_data_for_site(self, site_id: str, device_id: str, 
                                  namespace: Optional[str] = None) -> List[Dict]:
        """
        获取站点流量数据
        
        Args:
            site_id: 站点ID
            device_id: 设备ID
            namespace: 命名空间（中心机模式下的集群ID）
            
        Returns:
            流量数据点列表
        """
        all_data_points = []
        
        try:
            # 获取时间范围
            end_time = datetime.now()
            last_run_time = self.get_last_run_time()
            
            if last_run_time:
                start_time = last_run_time
                # 限制最大时间范围
                max_time_ranges = {
                    'mins': timedelta(hours=24),
                    'hours': timedelta(days=7),
                    'days': timedelta(days=30)
                }
                max_range = max_time_ranges.get(self.data_type, timedelta(hours=24))
                min_start_time = end_time - max_range
                
                if start_time < min_start_time:
                    logger.warning(f"时间范围太大，限制为最近 {max_range}")
                    start_time = min_start_time
            else:
                # 首次运行
                time_windows = {
                    'mins': timedelta(minutes=5),
                    'hours': timedelta(hours=2),
                    'days': timedelta(days=2)
                }
                time_window = time_windows.get(self.data_type, timedelta(minutes=5))
                start_time = end_time - time_window
            
            # 构建请求参数
            params = {
                "type": self.data_type,
                "app_id": site_id,
                "device_id": device_id,
                "timestamp__ge": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "timestamp__lt": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "_ts": int(time.time() * 1000)
            }
            
            # 中心机模式需要namespace参数
            if namespace and namespace not in ["0", None]:
                params["namespace"] = namespace
                logger.debug(f"使用namespace: {namespace}")
            
            response = self.session.get(
                f"{self.waf_host}/api/v1/logs/traffic/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "SUCCESS":
                    results = data.get("data", {}).get("result", [])
                    
                    for record in results:
                        # 检查有效数据
                        valid_data = False
                        for key, value in record.items():
                            if key != "timestamp" and value != "-":
                                valid_data = True
                                break
                        
                        if valid_data:
                            # 解析时间戳
                            timestamp_str = record.get('timestamp', '')
                            timestamp = int(time.time())
                            if timestamp_str:
                                try:
                                    dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                                    timestamp = int(dt.timestamp())
                                except Exception:
                                    pass
                            
                            # 构建数据点
                            data_point = {
                                'timestamp': timestamp,
                                'bytesInRateAvg': self._parse_metric(record.get('bytes_in_rate_avg')),
                                'bytesInRateMax': self._parse_metric(record.get('bytes_in_rate_max')),
                                'bytesOutRateAvg': self._parse_metric(record.get('bytes_out_rate_avg')),
                                'bytesOutRateMax': self._parse_metric(record.get('bytes_out_rate_max')),
                                'connCurAvg': self._parse_metric(record.get('conn_cur_avg')),
                                'connCurMax': self._parse_metric(record.get('conn_cur_max')),
                                'connRateAvg': self._parse_metric(record.get('conn_rate_avg')),
                                'httpReqCntAvg': self._parse_metric(record.get('http_req_cnt_avg')),
                                'httpReqCntMax': self._parse_metric(record.get('http_req_cnt_max')),
                                'httpReqRateAvg': self._parse_metric(record.get('http_req_rate_avg'))
                            }
                            all_data_points.append(data_point)
                    
                    if all_data_points:
                        logger.debug(f"站点 {site_id} 获取到 {len(all_data_points)} 个数据点")
                        
        except Exception as e:
            logger.error(f"获取站点 {site_id} 流量数据失败: {e}")
        
        # 如果没有数据，返回零值数据点
        if not all_data_points:
            all_data_points.append({
                'timestamp': int(time.time()),
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
            })
        
        return all_data_points
    
    def _parse_metric(self, value: Any) -> float:
        """解析指标值"""
        if value is None or value == "-":
            return 0.0
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0
    
    def get_last_run_time(self) -> Optional[datetime]:
        """获取上次运行时间"""
        try:
            if os.path.exists(self.last_run_file):
                with open(self.last_run_file, 'r') as f:
                    data = json.load(f)
                    last_run = data.get('last_run_time')
                    if last_run:
                        try:
                            return datetime.fromisoformat(last_run)
                        except (AttributeError, ValueError):
                            # Python 3.6兼容
                            if 'T' in last_run:
                                if '.' in last_run:
                                    return datetime.strptime(last_run[:26], "%Y-%m-%dT%H:%M:%S.%f")
                                else:
                                    return datetime.strptime(last_run, "%Y-%m-%dT%H:%M:%S")
                            else:
                                return datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            logger.debug(f"读取上次运行时间失败: {e}")
        return None
    
    def save_last_run_time(self, run_time: datetime):
        """保存本次运行时间"""
        try:
            data = {
                'last_run_time': run_time.isoformat(),
                'data_type': self.data_type,
                'zabbix_host': self.zabbix_host,
                'deployment_mode': self.deployment_mode
            }
            with open(self.last_run_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"保存运行时间到 {self.last_run_file}")
        except Exception as e:
            logger.error(f"保存运行时间失败: {e}")
    
    def collect_all_data(self) -> List[Dict]:
        """
        收集所有数据（中心机模式）
        
        Returns:
            Zabbix数据列表
        """
        all_data = []
        timestamp = int(time.time())
        
        # 检测部署模式
        mode = self.detect_deployment_mode()
        
        # 添加采集器状态
        all_data.append({
            'host': self.zabbix_host,
            'key': 'waf.collector.status',
            'value': 1,
            'clock': timestamp
        })
        
        all_data.append({
            'host': self.zabbix_host,
            'key': 'waf.collector.timestamp',
            'value': timestamp,
            'clock': timestamp
        })
        
        all_data.append({
            'host': self.zabbix_host,
            'key': 'waf.deployment.mode',
            'value': mode,
            'clock': timestamp
        })
        
        if mode == "center":
            # 中心机模式（唯一支持的模式）
            logger.info("开始采集中心机模式数据")
            
            # 1. 先获取所有站点信息（需要先获取以便统计集群站点数）
            sites = self.get_sites_with_domains()
            
            # 统计每个集群的站点数
            cluster_site_counts = {}
            for site in sites:
                cluster_id = site.get('cluster_id', '')
                if cluster_id:
                    cluster_site_counts[cluster_id] = cluster_site_counts.get(cluster_id, 0) + 1
            
            # 2. 获取并发送集群发现数据（如果API可用）
            clusters = self.get_clusters()
            if clusters:
                cluster_discovery = []
                for cluster_id, cluster_info in clusters.items():
                    # 更新站点数量
                    site_count = cluster_site_counts.get(cluster_id, cluster_info.get('site_count', 0))
                    cluster_discovery.append({
                        "{#CLUSTER_ID}": cluster_id,
                        "{#CLUSTER_NAME}": cluster_info.get('name', ''),
                        "{#CLUSTER_AREA}": cluster_info.get('area_name', cluster_info.get('area', '默认区域')),
                        "{#CLUSTER_TYPE}": cluster_info.get('type', cluster_info.get('deploy', '')),
                        "{#SITE_COUNT}": str(site_count)
                    })
                
                if cluster_discovery:
                    discovery_json = json.dumps({"data": cluster_discovery}, ensure_ascii=False)
                    logger.info(f"集群发现数据内容: {discovery_json}")
                    all_data.append({
                        'host': self.zabbix_host,
                        'key': 'waf.clusters.discovery',
                        'value': discovery_json,
                        'clock': timestamp  # 使用采集时的时间戳
                    })
                    logger.info(f"发送 {len(cluster_discovery)} 个集群发现数据")
            else:
                logger.warning("未获取到集群信息，跳过集群发现数据")
            
            # 3. 发送站点发现数据
            site_discovery = []
            
            for site in sites:
                # 对于每个站点创建发现项
                # 现在站点数据中包含了正确的节点信息
                site_discovery.append({
                    "{#SITE_ID}": site['id'],
                    "{#SITE_NAME}": site['name'],
                    "{#SITE_TYPE}": site['type'],
                    "{#SITE_ENABLE}": "1" if site.get('enabled', True) else "0",
                    "{#CLUSTER_ID}": site.get('cluster_id', ''),
                    "{#CLUSTER_NAME}": site.get('cluster_name', ''),
                    "{#CLUSTER_AREA}": site.get('area_name', ''),
                    "{#NODE_ID}": site.get('node_id', ''),
                    "{#NODE_NAME}": site.get('node_name', ''),  # 现在有具体的节点名称
                    "{#NODE_IP}": site.get('node_ip', '')  # 节点IP
                })
            
            if site_discovery:
                all_data.append({
                    'host': self.zabbix_host,
                    'key': 'waf.sites.discovery',
                    'value': json.dumps({"data": site_discovery}, ensure_ascii=False),
                    'clock': timestamp  # 使用采集时的时间戳
                })
                logger.info(f"发送 {len(site_discovery)} 个站点发现数据")
            
            # 4. 收集流量数据
            # 直接处理站点列表
            for site in sites:
                # 对于v2 API获取的站点，使用node_id作为device_id
                device_id = site.get('node_id') or site.get('device_id')
                if not device_id:
                    logger.warning(f"站点 {site['name']} 没有有效的device_id，跳过")
                    continue
                
                # 获取流量数据
                # 对于v2 API，namespace使用cluster_id；对于v1 API，使用struct_pk
                namespace = site.get('cluster_id') or (site.get('struct_pk') if site.get('struct_pk') != "0" else None)
                traffic_data = self.get_traffic_data_for_site(
                    site['id'],
                    device_id,
                    namespace
                )
                
                # 使用节点ID和站点ID组合作为唯一标识
                node_id = site.get('node_id', '')
                site_id = site['id']
                site_key = f"{node_id},{site_id}"
                
                # 站点状态
                all_data.append({
                    'host': self.zabbix_host,
                    'key': f"waf.site.status[{site_key}]",
                    'value': 1 if site.get('enabled', True) else 0,
                    'clock': timestamp
                })
                
                # 流量数据
                for data_point in traffic_data:
                    # 入站流量
                    all_data.append({
                        'host': self.zabbix_host,
                        'key': f"waf.site.traffic.in.avg[{site_key}]",
                        'value': data_point['bytesInRateAvg'],
                        'clock': data_point['timestamp']
                    })
                    all_data.append({
                        'host': self.zabbix_host,
                        'key': f"waf.site.traffic.in.max[{site_key}]",
                        'value': data_point['bytesInRateMax'],
                        'clock': data_point['timestamp']
                    })
                    
                    # 出站流量
                    all_data.append({
                        'host': self.zabbix_host,
                        'key': f"waf.site.traffic.out.avg[{site_key}]",
                        'value': data_point['bytesOutRateAvg'],
                        'clock': data_point['timestamp']
                    })
                    all_data.append({
                        'host': self.zabbix_host,
                        'key': f"waf.site.traffic.out.max[{site_key}]",
                        'value': data_point['bytesOutRateMax'],
                        'clock': data_point['timestamp']
                    })
                    
                    # 连接数
                    all_data.append({
                        'host': self.zabbix_host,
                        'key': f"waf.site.conn.cur.avg[{site_key}]",
                        'value': data_point['connCurAvg'],
                        'clock': data_point['timestamp']
                    })
                    all_data.append({
                        'host': self.zabbix_host,
                        'key': f"waf.site.conn.cur.max[{site_key}]",
                        'value': data_point['connCurMax'],
                        'clock': data_point['timestamp']
                    })
                    
                    # HTTP请求
                    all_data.append({
                        'host': self.zabbix_host,
                        'key': f"waf.site.http.req.rate[{site_key}]",
                        'value': data_point['httpReqRateAvg'],
                        'clock': data_point['timestamp']
                    })
                
                logger.info(f"节点 {site.get('node_name', 'N/A')} - 站点 {site['name']} 生成监控数据")
            
        
        # 保存运行时间
        self.save_last_run_time(datetime.now())
        
        return all_data
    
    def send_to_zabbix(self, data: List[Dict]) -> bool:
        """
        通过zabbix_sender发送数据
        
        Args:
            data: 要发送的数据列表
            
        Returns:
            是否成功
        """
        if not data:
            logger.warning("没有数据需要发送")
            return True
        
        try:
            # 验证数据格式
            for i, item in enumerate(data):
                if not item.get('host'):
                    logger.error(f"数据项 {i} 缺少 host 字段: {item}")
                    return False
                if not item.get('key'):
                    logger.error(f"数据项 {i} 缺少 key 字段: {item}")
                    return False
                if 'value' not in item:
                    logger.error(f"数据项 {i} 缺少 value 字段: {item}")
                    return False
            
            # 创建临时文件（使用文本格式，与成功的旧版本一致）
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for item in data:
                    # 对包含空格或特殊字符的key和value进行引号包装
                    host = item["host"]
                    key = item["key"]
                    value = item["value"]
                    
                    # clock是可选的
                    if "clock" in item and item["clock"]:
                        clock = item["clock"]
                    else:
                        clock = ""
                    
                    # 确保数值类型的值不被当作字符串
                    if isinstance(value, (int, float)):
                        value = str(value)
                    
                    # 如果key包含空格，需要用引号包装
                    # 注意：根据Zabbix文档，包含方括号的key不需要引号
                    if ' ' in key and '[' not in key:
                        key = f'"{key}"'
                    
                    # 如果value是字符串且包含空格或特殊字符，需要用引号包装
                    if isinstance(value, str) and (' ' in value or '"' in value or '\n' in value):
                        # 转义内部的引号
                        value = value.replace('\\', '\\\\').replace('"', '\\"')
                        value = f'"{value}"'
                    
                    # 格式: hostname key timestamp value
                    # 使用 -T 参数时，所有行都需要有时间戳
                    line = f'{host} {key} {clock} {value}\n'
                    f.write(line)
                    
                temp_file = f.name
            
            # 保存调试文件
            debug_file = f'/tmp/zabbix_sender_debug_{int(time.time())}.txt'
            with open(debug_file, 'w') as df:
                with open(temp_file, 'r') as tf:
                    content = tf.read()
                    df.write(content)
                    # 打印自动发现数据的详细内容
                    lines = content.split('\n')
                    for i, line in enumerate(lines[:20]):  # 打印前20行
                        if line.strip():  # 跳过空行
                            # 分析每一行的格式
                            parts = line.strip().split(' ')
                            if len(parts) >= 3:
                                key = parts[1]
                                # 打印数值类型的监控项
                                if any(k in key for k in ['traffic', 'conn', 'http.req', 'collector']):
                                    logger.debug(f"行 {i+1} - 键值: {key}, 字段数: {len(parts)}")
                                    if len(parts) == 4:
                                        logger.debug(f"  格式: host={parts[0][:20]}... key={parts[1]} timestamp={parts[2]} value={parts[3]}")
                                    elif len(parts) == 3:
                                        logger.debug(f"  格式: host={parts[0][:20]}... key={parts[1]} value={parts[2]}")
                            
                            if 'discovery' in line:
                                logger.info(f"发现数据行 {i+1}: {line[:200]}...")
                                parts = line.split(' ', 3)
                                if len(parts) >= 3:
                                    try:
                                        # 去掉引号并解析JSON
                                        json_str = parts[2] if len(parts) == 3 else parts[3]
                                        json_str = json_str.strip()
                                        if json_str.startswith('"') and json_str.endswith('"'):
                                            json_str = json_str[1:-1]
                                            # 反转义
                                            json_str = json_str.replace('\\"', '"').replace('\\\\', '\\')
                                            discovery_data = json.loads(json_str)
                                            logger.info(f"解析后的发现数据: {json.dumps(discovery_data, ensure_ascii=False, indent=2)[:500]}...")
                                    except Exception as e:
                                        logger.error(f"解析发现数据失败: {e}")
            logger.debug(f"调试文件已保存到: {debug_file}")
            
            # 构建zabbix_sender命令（使用文本格式输入）
            cmd = [
                'zabbix_sender',
                '-z', self.zabbix_server,
                '-i', temp_file,
                '-T',   # 使用带时间戳的格式
                '-vv'   # 增加详细输出
            ]
            
            logger.info(f"发送 {len(data)} 条数据到Zabbix")
            
            # 执行命令
            process = Popen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            
            # 保留临时文件用于调试
            if process.returncode != 0:
                logger.error(f"临时文件保留在: {temp_file}")
                # 读取文件前几行用于调试
                try:
                    with open(temp_file, 'r') as f:
                        lines = f.readlines()[:10]
                        logger.error(f"文件前10行内容:")
                        for i, line in enumerate(lines, 1):
                            logger.error(f"  行{i}: {line.rstrip()[:200]}")
                except Exception as e:
                    logger.error(f"无法读取临时文件: {e}")
            else:
                # 成功时清理临时文件
                try:
                    os.unlink(temp_file)
                except:
                    pass
            
            # 解析输出以获取更详细的信息
            stdout_str = stdout.decode() if stdout else ""
            stderr_str = stderr.decode() if stderr else ""
            
            # 检查是否有部分成功
            success_count = 0
            failed_count = 0
            if "processed:" in stdout_str:
                import re
                match = re.search(r'processed: (\d+); failed: (\d+)', stdout_str)
                if match:
                    success_count = int(match.group(1))
                    failed_count = int(match.group(2))
            
            if process.returncode == 0:
                logger.info(f"数据发送成功: {stdout_str}")
                return True
            else:
                logger.error(f"数据发送失败，返回码: {process.returncode}")
                logger.error(f"成功: {success_count}, 失败: {failed_count}")
                logger.error(f"错误信息: {stderr_str}")
                logger.error(f"标准输出: {stdout_str}")
                logger.error(f"使用的命令: {' '.join(cmd)}")
                
                # 如果有失败的项目，尝试分析
                if failed_count > 0 and "-T" in cmd:
                    logger.error("失败的监控项详情请查看上面的输出")
                
                # 检查zabbix_sender是否存在
                check_cmd = ['which', 'zabbix_sender']
                check_process = Popen(check_cmd, stdout=PIPE, stderr=PIPE)
                check_stdout, _ = check_process.communicate()
                if check_process.returncode != 0:
                    logger.error("未找到zabbix_sender命令，请确保已安装zabbix-sender包")
                    logger.error("安装命令: yum install -y zabbix-sender 或 apt-get install zabbix-sender")
                else:
                    logger.debug(f"zabbix_sender路径: {check_stdout.decode().strip()}")
                
                return False
                
        except Exception as e:
            logger.error(f"发送数据到Zabbix失败: {e}")
            return False
    
    def run(self) -> int:
        """
        执行采集任务
        
        Returns:
            退出码
        """
        try:
            logger.info("开始WAF数据采集")
            
            # 收集所有数据
            all_data = self.collect_all_data()
            
            if not all_data:
                logger.warning("没有收集到任何数据")
                return 1
            
            # 发送到Zabbix
            if self.send_to_zabbix(all_data):
                logger.info("数据采集和发送完成")
                # 输出成功状态供Zabbix判断
                print(1)
                return 0
            else:
                logger.error("数据发送失败")
                print(0)
                return 1
                
        except Exception as e:
            logger.error(f"采集过程出错: {e}", exc_info=True)
            print(0)
            return 1


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='WAF中心机数据采集器')
    parser.add_argument('--host', required=True, help='WAF管理地址')
    parser.add_argument('--token', required=True, help='API Token')
    parser.add_argument('--zabbix-server', required=True, help='Zabbix服务器地址')
    parser.add_argument('--zabbix-host', required=True, help='Zabbix中的主机名')
    parser.add_argument('--data-type', choices=['mins', 'hours', 'days'], 
                       default='mins', help='数据粒度类型')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 创建采集器并运行
    collector = WAFCenterCollector(
        waf_host=args.host,
        token=args.token,
        zabbix_server=args.zabbix_server,
        zabbix_host=args.zabbix_host,
        data_type=args.data_type
    )
    
    return collector.run()


if __name__ == "__main__":
    sys.exit(main())