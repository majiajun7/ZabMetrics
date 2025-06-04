# WAF监控系统使用说明

本项目提供了一套完整的明御WAF监控解决方案，通过Zabbix实现对WAF站点流量的实时监控。

## 系统组成

### 1. 监控脚本
- **waf_sender.py** - 主监控脚本，使用Zabbix Sender批量发送数据
- **waf_site_discovery.py** - 站点自动发现脚本（独立使用）
- **waf_traffic_collector.py** - 流量数据采集脚本（独立使用）

### 2. Zabbix模板
- **zabbix_template_waf_sender_6.0.xml** - Zabbix 6.0监控模板

## 功能特性

### 监控项
1. **采集器状态监控**
   - `waf.collector.status` - 采集器运行状态
   - `waf.collector.timestamp` - 最后采集时间戳

2. **站点自动发现（LLD）**
   - `waf.sites.discovery` - 自动发现所有WAF站点

3. **站点监控指标**
   - 站点启用状态
   - 入站/出站流量速率（平均值和最大值）
   - 当前连接数（平均值和最大值）
   - 连接速率
   - HTTP请求数和请求速率

### 触发器
- 站点禁用告警
- 流量过高告警
- 连接数过高告警
- HTTP请求速率过高告警
- 数据采集失败告警

### 图形展示
- 流量趋势图
- 连接数趋势图
- HTTP请求趋势图

## 部署步骤

### 1. 环境准备
```bash
# 安装Python依赖
pip install -r requirements.txt

# 确保安装了zabbix-sender
yum install zabbix-sender  # CentOS/RHEL
apt-get install zabbix-sender  # Ubuntu/Debian
```

### 2. 导入Zabbix模板
1. 登录Zabbix Web界面
2. 进入"配置" -> "模板"
3. 点击"导入"，选择`zabbix_template_waf_sender_6.0.xml`
4. 确认导入

### 3. 创建主机并关联模板
1. 进入"配置" -> "主机"
2. 创建新主机，设置主机名（如：WAF-Monitor）
3. 关联模板"Template WAF Traffic Monitor Sender"
4. 保存配置

### 4. 配置定时任务
```bash
# 编辑crontab
crontab -e

# 每分钟执行一次数据采集
* * * * * /usr/bin/python3 /path/to/waf_sender.py --waf-host https://WAF_IP:8443 --token YOUR_API_TOKEN --zabbix-server ZABBIX_IP --zabbix-host WAF-Monitor >> /var/log/waf_monitor.log 2>&1
```

## 使用示例

### 手动执行测试
```bash
# 基本执行
python3 waf_sender.py \
    --waf-host https://192.168.1.100:8443 \
    --token "your_api_token_here" \
    --zabbix-server 10.0.0.10 \
    --zabbix-host WAF-Monitor

# 调试模式
python3 waf_sender.py \
    --waf-host https://192.168.1.100:8443 \
    --token "your_api_token_here" \
    --zabbix-server 10.0.0.10 \
    --zabbix-host WAF-Monitor \
    --debug
```

### 独立使用站点发现
```bash
python3 waf_site_discovery.py \
    --host https://192.168.1.100:8443 \
    --token "your_api_token_here"
```

### 独立采集流量数据
```bash
python3 waf_traffic_collector.py \
    --host https://192.168.1.100:8443 \
    --token "your_api_token_here" \
    --app-id "site_id_here" \
    --all
```

## 故障排查

### 1. 检查连接
```bash
# 测试WAF API连接
curl -k -H "Authorization: Bearer YOUR_TOKEN" https://WAF_IP:8443/api/v1/device/name/

# 测试Zabbix连接
zabbix_sender -z ZABBIX_IP -s WAF-Monitor -k waf.collector.status -o 1
```

### 2. 查看日志
```bash
# 查看cron执行日志
tail -f /var/log/waf_monitor.log

# 查看Zabbix服务器日志
tail -f /var/log/zabbix/zabbix_server.log
```

### 3. 常见问题

**Q: 站点发现没有数据**
A: 检查API Token权限，确保能访问站点列表API

**Q: 流量数据全是0**
A: 检查device_id是否正确，某些站点可能需要特定的device_id

**Q: zabbix_sender命令未找到**
A: 需要安装zabbix-sender包

## 监控数据说明

### 流量单位
- 所有流量数据单位为bps（比特每秒）
- 原始数据从字节转换为比特（乘以8）

### 数据更新频率
- 建议每分钟采集一次
- 站点发现数据会在每次采集时更新

### 性能优化
- 使用批量发送减少网络开销
- 缓存设备ID减少API调用
- 站点禁用时发送0值，保持数据连续性

## 许可证

本项目遵循MIT许可证。