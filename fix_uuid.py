#!/usr/bin/env python3
"""修复Zabbix模板中的UUID格式"""

import xml.etree.ElementTree as ET
import uuid
import sys

def generate_zabbix_uuid():
    """生成Zabbix需要的32字符UUID（不带连字符）"""
    return str(uuid.uuid4()).replace('-', '')

def fix_uuids_in_xml(file_path):
    """修复XML文件中的所有UUID"""
    try:
        # 解析XML文件
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # 查找所有uuid标签
        uuid_count = 0
        for elem in root.iter('uuid'):
            # 生成新的32字符UUID
            new_uuid = generate_zabbix_uuid()
            elem.text = new_uuid
            uuid_count += 1
            print(f"替换UUID: {elem.text[:8]}... -> {new_uuid[:8]}...")
        
        # 保存修改后的文件
        tree.write(file_path, encoding='UTF-8', xml_declaration=True)
        
        print(f"\n成功修复 {uuid_count} 个UUID")
        print(f"文件已保存: {file_path}")
        
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    file_path = "/Users/jayson/Downloads/ZabMetrics/zabbix_template_waf_sender_6.0.xml"
    print(f"正在修复文件: {file_path}")
    fix_uuids_in_xml(file_path)