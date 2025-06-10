package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// WAFCollector WAF数据采集器
type WAFCollector struct {
	wafHost        string
	token          string
	zabbixServer   string
	zabbixHost     string
	dataType       string
	client         *http.Client
	cachedSites    []Site
	cachedDeviceID string
	lastRunFile    string
}

// Site 站点信息
type Site struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	StructID string `json:"struct_id"`
}

// TrafficData 流量数据
type TrafficData struct {
	Timestamp       int64   `json:"timestamp"`
	BytesInRateAvg  float64 `json:"bytesInRateAvg"`
	BytesInRateMax  float64 `json:"bytesInRateMax"`
	BytesOutRateAvg float64 `json:"bytesOutRateAvg"`
	BytesOutRateMax float64 `json:"bytesOutRateMax"`
	ConnCurAvg      float64 `json:"connCurAvg"`
	ConnCurMax      float64 `json:"connCurMax"`
	ConnRateAvg     float64 `json:"connRateAvg"`
	HTTPReqCntAvg   float64 `json:"httpReqCntAvg"`
	HTTPReqCntMax   float64 `json:"httpReqCntMax"`
	HTTPReqRateAvg  float64 `json:"httpReqRateAvg"`
}

// ZabbixData Zabbix数据项
type ZabbixData struct {
	Host  string      `json:"host"`
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
	Clock int64       `json:"clock"`
}

// LastRunInfo 上次运行信息
type LastRunInfo struct {
	LastRunTime string `json:"last_run_time"`
	DataType    string `json:"data_type"`
	ZabbixHost  string `json:"zabbix_host"`
}

// APIResponse 通用API响应结构
type APIResponse struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// NewWAFCollector 创建WAF采集器
func NewWAFCollector(wafHost, token, zabbixServer, zabbixHost, dataType string) *WAFCollector {
	// 创建HTTP客户端，忽略SSL证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	// 生成上次运行时间文件路径
	safeHost := strings.ReplaceAll(zabbixHost, "/", "_")
	lastRunFile := filepath.Join("/tmp", fmt.Sprintf("waf_sender_last_run_%s.json", safeHost))

	return &WAFCollector{
		wafHost:      strings.TrimRight(wafHost, "/"),
		token:        token,
		zabbixServer: zabbixServer,
		zabbixHost:   zabbixHost,
		dataType:     dataType,
		client:       client,
		lastRunFile:  lastRunFile,
	}
}

// doRequest 执行HTTP请求
func (w *WAFCollector) doRequest(method, path string, params map[string]string) (*APIResponse, error) {
	url := fmt.Sprintf("%s%s", w.wafHost, path)
	
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))

	// 添加查询参数
	if params != nil {
		q := req.URL.Query()
		for k, v := range params {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP错误: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	if apiResp.Code != "SUCCESS" {
		return nil, fmt.Errorf("API错误: %s", apiResp.Message)
	}

	return &apiResp, nil
}

// login 验证连接
func (w *WAFCollector) login() bool {
	_, err := w.doRequest("GET", "/api/v1/device/name/", nil)
	if err != nil {
		log.Printf("WAF连接验证失败: %v", err)
		return false
	}
	log.Println("WAF连接验证成功")
	return true
}

// getDeviceID 获取设备ID
func (w *WAFCollector) getDeviceID() string {
	if w.cachedDeviceID != "" {
		return w.cachedDeviceID
	}

	params := map[string]string{
		"_ts": fmt.Sprintf("%d", time.Now().UnixMilli()),
	}

	resp, err := w.doRequest("GET", "/api/v1/device/name/", params)
	if err != nil {
		log.Printf("获取设备ID失败: %v", err)
		return ""
	}

	var deviceInfo struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.Data, &deviceInfo); err != nil {
		log.Printf("解析设备信息失败: %v", err)
		return ""
	}

	w.cachedDeviceID = deviceInfo.ID
	log.Printf("获取到设备ID: %s", w.cachedDeviceID)
	return w.cachedDeviceID
}

// getDeviceSerial 获取设备序列号作为备用device_id
func (w *WAFCollector) getDeviceSerial() string {
	resp, err := w.doRequest("GET", "/api/v1/device/info/", nil)
	if err != nil {
		return ""
	}

	var deviceInfo struct {
		Serial string `json:"serial"`
	}
	if err := json.Unmarshal(resp.Data, &deviceInfo); err != nil {
		return ""
	}

	return deviceInfo.Serial
}

// getSites 获取所有站点信息
func (w *WAFCollector) getSites() []Site {
	params := map[string]string{
		"page":     "1",
		"per_page": "1000",
		"_ts":      fmt.Sprintf("%d", time.Now().UnixMilli()),
	}

	resp, err := w.doRequest("GET", "/api/v1/website/site/", params)
	if err != nil {
		log.Printf("获取站点列表失败: %v", err)
		return nil
	}

	var siteData struct {
		Result []struct {
			PK       string `json:"_pk"`
			Name     string `json:"name"`
			Enable   bool   `json:"enable"`
			StructPK string `json:"struct_pk"`
		} `json:"result"`
	}

	if err := json.Unmarshal(resp.Data, &siteData); err != nil {
		log.Printf("解析站点数据失败: %v", err)
		return nil
	}

	sites := make([]Site, 0, len(siteData.Result))
	for _, s := range siteData.Result {
		sites = append(sites, Site{
			ID:       s.PK,
			Name:     s.Name,
			Enabled:  s.Enable,
			StructID: s.StructPK,
		})
	}

	log.Printf("发现 %d 个站点", len(sites))
	w.cachedSites = sites
	return sites
}

// getLastRunTime 获取上次运行时间
func (w *WAFCollector) getLastRunTime() *time.Time {
	data, err := os.ReadFile(w.lastRunFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("读取上次运行时间文件失败: %v", err)
		}
		return nil
	}

	var info LastRunInfo
	if err := json.Unmarshal(data, &info); err != nil {
		log.Printf("解析上次运行时间失败: %v", err)
		return nil
	}

	// 兼容多种时间格式（参考Python版本）
	var t time.Time
	var parseErr error
	
	// 尝试RFC3339格式 (2006-01-02T15:04:05Z07:00)
	t, parseErr = time.Parse(time.RFC3339, info.LastRunTime)
	if parseErr != nil {
		// 尝试ISO格式带微秒 (2006-01-02T15:04:05.999999)
		t, parseErr = time.Parse("2006-01-02T15:04:05.999999", info.LastRunTime)
		if parseErr != nil {
			// 尝试ISO格式不带微秒 (2006-01-02T15:04:05)
			t, parseErr = time.Parse("2006-01-02T15:04:05", info.LastRunTime)
			if parseErr != nil {
				// 尝试普通格式 (2006-01-02 15:04:05)
				t, parseErr = time.Parse("2006-01-02 15:04:05", info.LastRunTime)
				if parseErr != nil {
					log.Printf("解析时间格式失败: %v", parseErr)
					return nil
				}
			}
		}
	}

	log.Printf("读取到上次运行时间: %s", t.Format("2006-01-02 15:04:05"))
	return &t
}

// saveLastRunTime 保存本次运行时间
func (w *WAFCollector) saveLastRunTime(runTime time.Time) {
	info := LastRunInfo{
		LastRunTime: runTime.Format(time.RFC3339),
		DataType:    w.dataType,
		ZabbixHost:  w.zabbixHost,
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		log.Printf("序列化运行时间失败: %v", err)
		return
	}

	if err := os.WriteFile(w.lastRunFile, data, 0644); err != nil {
		log.Printf("保存运行时间失败: %v", err)
		return
	}
}

// findWorkingDeviceID 智能查找可用的device_id
func (w *WAFCollector) findWorkingDeviceID(appID, originalDeviceID string) string {
	// 处理"0"、"auto"或空值的情况
	if originalDeviceID == "" || originalDeviceID == "0" || originalDeviceID == "auto" {
		realDeviceID := w.getDeviceID()
		if realDeviceID != "" {
			log.Printf("站点 %s 的device_id是'%s'，使用真实设备ID: %s", appID, originalDeviceID, realDeviceID)
			return realDeviceID
		}
	}

	// 尝试使用原始device_id
	if w.tryGetData(appID, originalDeviceID) {
		return originalDeviceID
	}

	// 尝试其他方法查找
	log.Printf("原始device_id %s 未返回有效数据，尝试其他方法...", originalDeviceID)

	// 方法1：从站点列表查找struct_pk
	for _, site := range w.cachedSites {
		if site.ID == appID && site.StructID != "" && site.StructID != originalDeviceID && site.StructID != "0" {
			if w.tryGetData(appID, site.StructID) {
				return site.StructID
			}
			break
		}
	}

	// 方法2：尝试从设备名称接口获取UUID格式的device_id
	realDeviceID := w.getDeviceID()
	if realDeviceID != "" && realDeviceID != originalDeviceID {
		if w.tryGetData(appID, realDeviceID) {
			return realDeviceID
		}
	}

	// 方法3：尝试从集群拓扑查找（参考waf_traffic_collector.py）
	siteTypes := []string{"reverse", "transparent", "traction", "sniffer", "bridge"}
	for _, siteType := range siteTypes {
		treeURL := fmt.Sprintf("/api/v1/website/tree/%s/", siteType)
		resp, err := w.doRequest("GET", treeURL, nil)
		if err != nil {
			continue
		}

		var treeData []interface{}
		if err := json.Unmarshal(resp.Data, &treeData); err != nil {
			continue
		}

		// 遍历树形结构查找集群ID
		for _, item := range treeData {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if children, ok := itemMap["children"].([]interface{}); ok {
					for _, area := range children {
						if areaMap, ok := area.(map[string]interface{}); ok {
							if areaChildren, ok := areaMap["children"].([]interface{}); ok {
								for _, cluster := range areaChildren {
									if clusterMap, ok := cluster.(map[string]interface{}); ok {
										if clusterID, ok := clusterMap["_pk"].(string); ok {
											if clusterID != "" && clusterID != "0" && clusterID != "1" && clusterID != originalDeviceID {
												if w.tryGetData(appID, clusterID) {
													log.Printf("成功使用集群ID: %s", clusterID)
													return clusterID
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 方法4：最后尝试使用设备序列号作为备用（参考waf_traffic_collector.py）
	deviceSerial := w.getDeviceSerial()
	if deviceSerial != "" && deviceSerial != originalDeviceID {
		log.Printf("尝试使用设备序列号: %s", deviceSerial)
		if w.tryGetData(appID, deviceSerial) {
			return deviceSerial
		}
	}

	return originalDeviceID
}

// tryGetData 尝试使用指定的device_id获取数据
func (w *WAFCollector) tryGetData(appID, deviceID string) bool {
	params := map[string]string{
		"type":      "mins",
		"app_id":    appID,
		"device_id": deviceID,
		"_ts":       fmt.Sprintf("%d", time.Now().UnixMilli()),
	}

	resp, err := w.doRequest("GET", "/api/v1/logs/traffic/", params)
	if err != nil {
		return false
	}

	var trafficResp struct {
		Result []map[string]interface{} `json:"result"`
	}

	if err := json.Unmarshal(resp.Data, &trafficResp); err != nil {
		return false
	}

	// 检查是否有有效数据
	for _, record := range trafficResp.Result {
		for k, v := range record {
			if k != "timestamp" && v != "-" {
				return true
			}
		}
	}

	return false
}

// getTrafficData 获取站点流量数据
func (w *WAFCollector) getTrafficData(appID, deviceID string) []TrafficData {
	// 智能查找有效的device_id
	workingDeviceID := w.findWorkingDeviceID(appID, deviceID)

	// 确定时间范围
	endTime := time.Now()
	var startTime time.Time

	lastRunTime := w.getLastRunTime()
	if lastRunTime != nil {
		startTime = *lastRunTime
		
		// 限制最大时间范围
		maxRanges := map[string]time.Duration{
			"mins":  24 * time.Hour,
			"hours": 7 * 24 * time.Hour,
			"days":  30 * 24 * time.Hour,
		}
		
		maxRange := maxRanges[w.dataType]
		if maxRange == 0 {
			maxRange = 24 * time.Hour
		}
		
		minStartTime := endTime.Add(-maxRange)
		if startTime.Before(minStartTime) {
			log.Printf("时间范围太大，限制为最近 %v", maxRange)
			startTime = minStartTime
		}
		
		log.Printf("从上次运行时间获取数据: %s", lastRunTime.Format("2006-01-02 15:04:05"))
	} else {
		// 首次运行，根据数据类型确定时间窗口
		timeWindows := map[string]time.Duration{
			"mins":  5 * time.Minute,
			"hours": 2 * time.Hour,
			"days":  2 * 24 * time.Hour,
		}
		
		timeWindow := timeWindows[w.dataType]
		if timeWindow == 0 {
			timeWindow = 5 * time.Minute
		}
		
		startTime = endTime.Add(-timeWindow)
		log.Printf("首次运行，获取最近 %v 的数据", timeWindow)
	}

	// 请求参数
	params := map[string]string{
		"type":          w.dataType,
		"app_id":        appID,
		"device_id":     workingDeviceID,
		"timestamp__ge": startTime.Format("2006-01-02 15:04:05"),
		"timestamp__lt": endTime.Format("2006-01-02 15:04:05"),
		"_ts":           fmt.Sprintf("%d", time.Now().UnixMilli()),
	}

	log.Printf("请求流量数据，时间范围: %s 到 %s", startTime.Format("2006-01-02 15:04:05"), endTime.Format("2006-01-02 15:04:05"))

	resp, err := w.doRequest("GET", "/api/v1/logs/traffic/", params)
	if err != nil {
		log.Printf("获取流量数据失败 (app_id=%s): %v", appID, err)
		return []TrafficData{{Timestamp: time.Now().Unix()}}
	}

	var trafficResp struct {
		Result []map[string]interface{} `json:"result"`
	}

	if err := json.Unmarshal(resp.Data, &trafficResp); err != nil {
		log.Printf("解析流量数据失败: %v", err)
		return []TrafficData{{Timestamp: time.Now().Unix()}}
	}

	dataPoints := make([]TrafficData, 0)
	
	for _, record := range trafficResp.Result {
		// 检查是否有有效数据
		validData := false
		for k, v := range record {
			if k != "timestamp" && v != "-" {
				validData = true
				break
			}
		}

		if !validData {
			continue
		}

		// 解析时间戳
		var timestamp int64
		if tsStr, ok := record["timestamp"].(string); ok && tsStr != "" {
			t, err := time.Parse("2006-01-02 15:04:05", tsStr)
			if err == nil {
				timestamp = t.Unix()
			} else {
				timestamp = time.Now().Unix()
			}
		} else {
			timestamp = time.Now().Unix()
		}

		// 构建数据点
		dataPoint := TrafficData{
			Timestamp:       timestamp,
			BytesInRateAvg:  getFloatValue(record, "bytes_in_rate_avg"),
			BytesInRateMax:  getFloatValue(record, "bytes_in_rate_max"),
			BytesOutRateAvg: getFloatValue(record, "bytes_out_rate_avg"),
			BytesOutRateMax: getFloatValue(record, "bytes_out_rate_max"),
			ConnCurAvg:      getFloatValue(record, "conn_cur_avg"),
			ConnCurMax:      getFloatValue(record, "conn_cur_max"),
			ConnRateAvg:     getFloatValue(record, "conn_rate_avg"),
			HTTPReqCntAvg:   getFloatValue(record, "http_req_cnt_avg"),
			HTTPReqCntMax:   getFloatValue(record, "http_req_cnt_max"),
			HTTPReqRateAvg:  getFloatValue(record, "http_req_rate_avg"),
		}
		
		dataPoints = append(dataPoints, dataPoint)
	}

	if len(dataPoints) > 0 {
		log.Printf("站点 %s 使用数据类型 '%s' 获取到 %d 个有效数据点", appID, w.dataType, len(dataPoints))
		
		// 分析数据粒度间隔
		if len(dataPoints) > 1 {
			sort.Slice(dataPoints, func(i, j int) bool {
				return dataPoints[i].Timestamp < dataPoints[j].Timestamp
			})
			
			intervals := make([]int64, 0)
			for i := 1; i < len(dataPoints); i++ {
				interval := dataPoints[i].Timestamp - dataPoints[i-1].Timestamp
				intervals = append(intervals, interval)
			}
			
			if len(intervals) > 0 {
				var sum int64
				min := intervals[0]
				max := intervals[0]
				for _, interval := range intervals {
					sum += interval
					if interval < min {
						min = interval
					}
					if interval > max {
						max = interval
					}
				}
				avg := sum / int64(len(intervals))
				
				log.Printf("站点 %s 数据时间间隔统计:", appID)
				log.Printf("  - 最小间隔: %d 秒 (%.1f 分钟)", min, float64(min)/60)
				log.Printf("  - 最大间隔: %d 秒 (%.1f 分钟)", max, float64(max)/60)
				log.Printf("  - 平均间隔: %d 秒 (%.1f 分钟)", avg, float64(avg)/60)
			}
		}
	}

	// 如果没有数据，返回一个零数据点
	if len(dataPoints) == 0 {
		dataPoints = append(dataPoints, TrafficData{Timestamp: time.Now().Unix()})
	}

	return dataPoints
}

// getFloatValue 从map中获取float值
func getFloatValue(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return val
		case string:
			if val == "-" {
				return 0
			}
		}
	}
	return 0
}

// collectAllData 收集所有站点的数据
func (w *WAFCollector) collectAllData() []ZabbixData {
	// 登录验证
	if !w.login() {
		log.Println("无法登录WAF")
		return nil
	}

	// 获取设备ID
	deviceID := w.getDeviceID()
	if deviceID == "" {
		log.Println("无法获取设备ID，尝试使用默认值")
		deviceID = "default"
	}

	// 获取站点列表
	sites := w.getSites()
	if len(sites) == 0 {
		log.Println("未发现任何站点")
		return nil
	}

	// 收集数据
	allData := make([]ZabbixData, 0)
	timestamp := time.Now().Unix()

	// 添加采集器状态监控项
	allData = append(allData,
		ZabbixData{
			Host:  w.zabbixHost,
			Key:   "waf.collector.status",
			Value: 1,
			Clock: timestamp,
		},
		ZabbixData{
			Host:  w.zabbixHost,
			Key:   "waf.collector.timestamp",
			Value: timestamp,
			Clock: timestamp,
		},
	)

	// 构建站点发现数据
	discoveryData := make([]map[string]string, 0)
	for _, site := range sites {
		siteDeviceID := site.StructID
		if siteDeviceID == "0" || siteDeviceID == "" {
			siteDeviceID = deviceID
		}

		enableStr := "0"
		if site.Enabled {
			enableStr = "1"
		}

		discoveryData = append(discoveryData, map[string]string{
			"{#SITE_ID}":    site.ID,
			"{#SITE_NAME}":  site.Name,
			"{#SITE_TYPE}":  "WAF",
			"{#SITE_IP}":    "",
			"{#SITE_PORT}":  "",
			"{#SITE_DOMAIN}": "",
			"{#SITE_ENABLE}": enableStr,
			"{#STRUCT_ID}":  siteDeviceID,
			"{#DEVICE_ID}":  siteDeviceID,
			"{#STRUCT_PK}":  site.StructID,
		})
	}

	// 添加LLD数据
	discoveryJSON, _ := json.Marshal(map[string]interface{}{"data": discoveryData})
	allData = append(allData, ZabbixData{
		Host:  w.zabbixHost,
		Key:   "waf.sites.discovery",
		Value: string(discoveryJSON),
		Clock: timestamp,
	})

	// 收集每个站点的流量数据
	for _, site := range sites {
		siteName := site.Name

		// 站点状态
		statusValue := 0
		if site.Enabled {
			statusValue = 1
		}
		allData = append(allData, ZabbixData{
			Host:  w.zabbixHost,
			Key:   fmt.Sprintf("waf.site.status[%s]", siteName),
			Value: statusValue,
			Clock: timestamp,
		})

		// 获取流量数据
		if site.Enabled {
			actualDeviceID := deviceID
			if site.StructID != "0" {
				actualDeviceID = site.StructID
			}
			
			trafficDataPoints := w.getTrafficData(site.ID, actualDeviceID)
			
			// 处理所有数据点
			for _, trafficData := range trafficDataPoints {
				dataTimestamp := trafficData.Timestamp
				
				// 入站流量
				allData = append(allData,
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.bytes_in_rate_avg[%s]", siteName),
						Value: trafficData.BytesInRateAvg,
						Clock: dataTimestamp,
					},
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.bytes_in_rate_max[%s]", siteName),
						Value: trafficData.BytesInRateMax,
						Clock: dataTimestamp,
					},
				)
				
				// 出站流量
				allData = append(allData,
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.bytes_out_rate_avg[%s]", siteName),
						Value: trafficData.BytesOutRateAvg,
						Clock: dataTimestamp,
					},
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.bytes_out_rate_max[%s]", siteName),
						Value: trafficData.BytesOutRateMax,
						Clock: dataTimestamp,
					},
				)
				
				// 连接数
				allData = append(allData,
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.conn_cur_avg[%s]", siteName),
						Value: trafficData.ConnCurAvg,
						Clock: dataTimestamp,
					},
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.conn_cur_max[%s]", siteName),
						Value: trafficData.ConnCurMax,
						Clock: dataTimestamp,
					},
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.conn_rate_avg[%s]", siteName),
						Value: trafficData.ConnRateAvg,
						Clock: dataTimestamp,
					},
				)
				
				// HTTP请求
				allData = append(allData,
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.http_req_cnt_avg[%s]", siteName),
						Value: trafficData.HTTPReqCntAvg,
						Clock: dataTimestamp,
					},
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.http_req_cnt_max[%s]", siteName),
						Value: trafficData.HTTPReqCntMax,
						Clock: dataTimestamp,
					},
					ZabbixData{
						Host:  w.zabbixHost,
						Key:   fmt.Sprintf("waf.site.http_req_rate_avg[%s]", siteName),
						Value: trafficData.HTTPReqRateAvg,
						Clock: dataTimestamp,
					},
				)
			}
			
			log.Printf("站点 %s 收集了 %d 个数据点", siteName, len(trafficDataPoints))
		} else {
			// 站点禁用时，发送0值
			zeroKeys := []string{
				"bytes_in_rate_avg", "bytes_in_rate_max",
				"bytes_out_rate_avg", "bytes_out_rate_max",
				"conn_cur_avg", "conn_cur_max", "conn_rate_avg",
				"http_req_cnt_avg", "http_req_cnt_max", "http_req_rate_avg",
			}
			
			for _, key := range zeroKeys {
				allData = append(allData, ZabbixData{
					Host:  w.zabbixHost,
					Key:   fmt.Sprintf("waf.site.%s[%s]", key, siteName),
					Value: 0,
					Clock: timestamp,
				})
			}
		}
	}

	return allData
}

// sendToZabbix 发送数据到Zabbix
func (w *WAFCollector) sendToZabbix(data []ZabbixData) bool {
	if len(data) == 0 {
		log.Println("没有数据需要发送")
		return false
	}

	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "zabbix_sender_*.txt")
	if err != nil {
		log.Printf("创建临时文件失败: %v", err)
		return false
	}
	defer os.Remove(tmpFile.Name())

	// 写入数据
	for _, item := range data {
		key := item.Key
		value := fmt.Sprintf("%v", item.Value)
		
		// 如果key包含空格或特殊字符，需要用引号包装
		if strings.Contains(key, " ") || strings.Contains(key, "[") {
			key = fmt.Sprintf(`"%s"`, key)
		}
		
		// 如果value是字符串且包含特殊字符，需要用引号包装
		if strVal, ok := item.Value.(string); ok {
			if strings.Contains(strVal, " ") || strings.Contains(strVal, `"`) || strings.Contains(strVal, "\n") {
				// 转义内部的引号
				strVal = strings.ReplaceAll(strVal, `\`, `\\`)
				strVal = strings.ReplaceAll(strVal, `"`, `\"`)
				value = fmt.Sprintf(`"%s"`, strVal)
			}
		}
		
		line := fmt.Sprintf("%s %s %d %s\n", item.Host, key, item.Clock, value)
		if _, err := tmpFile.WriteString(line); err != nil {
			log.Printf("写入临时文件失败: %v", err)
			return false
		}
	}
	tmpFile.Close()

	log.Printf("临时文件路径: %s", tmpFile.Name())
	log.Printf("准备发送 %d 个数据项到Zabbix", len(data))
	
	// 统计发送数据的时间戳分布
	timestampsByKey := make(map[string]map[int64]bool)
	for _, item := range data {
		keyPrefix := strings.Split(item.Key, "[")[0]
		if strings.Contains(keyPrefix, "bytes") || strings.Contains(keyPrefix, "conn") || strings.Contains(keyPrefix, "http") {
			if _, ok := timestampsByKey[keyPrefix]; !ok {
				timestampsByKey[keyPrefix] = make(map[int64]bool)
			}
			timestampsByKey[keyPrefix][item.Clock] = true
		}
	}
	
	log.Println("发送数据的时间戳统计:")
	for keyPrefix, timestamps := range timestampsByKey {
		if len(timestamps) > 0 {
			log.Printf("  - %s: %d 个不同时间戳", keyPrefix, len(timestamps))
			if len(timestamps) > 1 {
				// 计算间隔
				var tsList []int64
				for ts := range timestamps {
					tsList = append(tsList, ts)
				}
				sort.Slice(tsList, func(i, j int) bool { return tsList[i] < tsList[j] })
				
				var intervals []int64
				for i := 1; i < len(tsList); i++ {
					intervals = append(intervals, tsList[i]-tsList[i-1])
				}
				
				if len(intervals) > 0 {
					var sum int64
					for _, interval := range intervals {
						sum += interval
					}
					avgInterval := float64(sum) / float64(len(intervals))
					log.Printf("    平均间隔: %.1f 秒 (%.1f 分钟)", avgInterval, avgInterval/60)
				}
			}
		}
	}

	// 检查zabbix_sender是否存在
	zabbixSenderPath, err := exec.LookPath("zabbix_sender")
	if err != nil {
		log.Printf("zabbix_sender命令未找到，请先安装zabbix-sender")
		return false
	}

	// 使用zabbix_sender发送
	cmd := exec.Command(zabbixSenderPath,
		"-z", w.zabbixServer,
		"-i", tmpFile.Name(),
		"-vv",
		"-T",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		log.Printf("Zabbix sender失败: %v", err)
		log.Printf("标准错误: %s", stderr.String())
		if stdout.Len() > 0 {
			log.Printf("标准输出: %s", stdout.String())
		}
		return false
	}

	log.Printf("成功发送 %d 个数据项到Zabbix", len(data))
	return true
}

// sendCollectorStatus 发送采集器状态
func (w *WAFCollector) sendCollectorStatus(status int) {
	data := []ZabbixData{
		{
			Host:  w.zabbixHost,
			Key:   "waf.collector.status",
			Value: status,
			Clock: time.Now().Unix(),
		},
	}
	w.sendToZabbix(data)
}

// run 运行采集器
func (w *WAFCollector) run() bool {
	log.Println("开始采集WAF数据...")
	
	// 记录本次运行时间
	currentRunTime := time.Now()
	
	// 收集数据
	data := w.collectAllData()
	
	if len(data) > 0 {
		log.Printf("收集到 %d 个数据项", len(data))
		
		// 发送到Zabbix
		if w.sendToZabbix(data) {
			log.Println("数据发送成功")
			// 成功后保存运行时间
			w.saveLastRunTime(currentRunTime)
			return true
		}
		
		log.Println("数据发送失败")
		w.sendCollectorStatus(0)
		return false
	}
	
	log.Println("未收集到任何数据")
	w.sendCollectorStatus(0)
	return false
}

func main() {
	// 命令行参数
	var (
		wafHost      = flag.String("waf-host", "", "WAF管理地址")
		token        = flag.String("token", "", "API认证令牌")
		zabbixServer = flag.String("zabbix-server", "", "Zabbix服务器地址")
		zabbixHost   = flag.String("zabbix-host", "", "Zabbix中的主机名")
		dataType     = flag.String("data-type", "mins", "数据粒度类型，可选：mins, hours, days")
		debug        = flag.Bool("debug", false, "启用调试模式")
		quiet        = flag.Bool("quiet", false, "静默模式，不输出日志")
	)
	
	flag.Parse()
	
	// 参数验证
	if *wafHost == "" || *token == "" || *zabbixServer == "" || *zabbixHost == "" {
		flag.Usage()
		os.Exit(1)
	}
	
	// 配置日志
	if *quiet {
		log.SetOutput(io.Discard)
	} else if !*debug {
		// 非调试模式下，只输出重要信息
		log.SetFlags(log.Ldate | log.Ltime)
	} else {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}
	
	// 创建采集器并运行
	collector := NewWAFCollector(*wafHost, *token, *zabbixServer, *zabbixHost, *dataType)
	
	// 执行数据采集
	success := collector.run()
	
	// 输出结果：0表示成功，1表示失败
	if success {
		fmt.Println(0)
		os.Exit(0)
	} else {
		fmt.Println(1)
		os.Exit(1)
	}
}