from flask import Flask, render_template, request, jsonify, Response
import subprocess
import re
import ipaddress
import socket
import psutil
import sqlite3
import os
import sys
import logging
import json
import webbrowser
import threading
import time
import configparser
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from openpyxl import Workbook
from io import BytesIO

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 确定应用程序根目录
isPackaged = not sys.argv[0].endswith('.py')
if isPackaged:
    # 应用程序已编译
    APP_ROOT = os.path.dirname(os.path.abspath(sys.argv[0]))
else:
    # 应用程序未编译
    APP_ROOT = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, template_folder=os.path.join(APP_ROOT, '.'), static_folder=os.path.join(APP_ROOT, 'static'))

config = configparser.ConfigParser()
config_path = os.path.join(APP_ROOT, 'config.ini')
logging.info(f"Application root directory: {APP_ROOT}")
logging.info(f"Config file path: {config_path}")

# 初始化默认配置
DETECTION_PORTS = [22, 80, 443, 3389]
WEB_SERVER_PORT = 5000
SCAN_THREAD_COUNT = 10
PRESET_IP_RANGES = []

# 版本检查默认配置
ENABLE_VERSION_CHECK = False
VERSION_CHECK_URL = ''
VERSION_CHECK_TIMEOUT = 5
VERSION_CHECK_MAX_ATTEMPTS = 3

if os.path.exists(config_path):
    config.read(config_path, encoding='utf-8')
    # 获取检测端口列表
    ports_str = config.get('Detection', 'Ports', fallback='22,80,443,3389')
    DETECTION_PORTS = list(map(int, ports_str.split(',')))
    logging.info(f"Loaded detection ports from config: {DETECTION_PORTS}")
    
    # 获取Web服务器配置
    WEB_SERVER_PORT = config.getint('WebServer', 'Port', fallback=5000)
    SCAN_THREAD_COUNT = config.getint('WebServer', 'ThreadCount', fallback=10)
    logging.info(f"Loaded web server config: port={WEB_SERVER_PORT}, thread count={SCAN_THREAD_COUNT}")
    
    # 获取预置IP段配置
    ip_ranges_str = config.get('Scan', 'PresetIPRanges', fallback='')
    PRESET_IP_RANGES = [ip_range.strip() for ip_range in ip_ranges_str.split(',') if ip_range.strip()]
    logging.info(f"Loaded preset IP ranges: {PRESET_IP_RANGES}")
    
    # 获取版本检查配置
    ENABLE_VERSION_CHECK = config.getboolean('VersionCheck', 'Enable', fallback=False)
    VERSION_CHECK_URL = config.get('VersionCheck', 'URL', fallback='')
    VERSION_CHECK_TIMEOUT = config.getint('VersionCheck', 'Timeout', fallback=5)
    VERSION_CHECK_MAX_ATTEMPTS = config.getint('VersionCheck', 'MaxAttempts', fallback=3)
    logging.info(f"Loaded version check config: enabled={ENABLE_VERSION_CHECK}, url={VERSION_CHECK_URL}, timeout={VERSION_CHECK_TIMEOUT}, max_attempts={VERSION_CHECK_MAX_ATTEMPTS}")
else:
    logging.info(f"Config file not found, using default settings")

class MACVendorDatabase:
    def __init__(self, db_path):
        self.vendor_dict = {}
        self.db_path = db_path
        self.load_data()

    def load_data(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM mac")
            rows = cursor.fetchall()

            for row in rows:
                if len(row) >= 3:
                    mac_prefix = str(row[1]).upper().strip()
                    vendor_name = str(row[2]).strip()
                    if mac_prefix and vendor_name:
                        self.vendor_dict[mac_prefix] = vendor_name

            conn.close()
        except Exception as e:
            print(f"Database load failed: {str(e)}")

    def get_vendor(self, mac_address):
        clean_mac = ''.join(c for c in mac_address.upper() if c in '0123456789ABCDEF')

        if len(clean_mac) < 6:
            return "未知厂商"

        prefix_6 = clean_mac[:6]
        if prefix_6 in self.vendor_dict:
            return self.vendor_dict[prefix_6]

        prefix_5 = clean_mac[:5]
        if prefix_5 in self.vendor_dict:
            return self.vendor_dict[prefix_5]

        prefix_4 = clean_mac[:4]
        if prefix_4 in self.vendor_dict:
            return self.vendor_dict[prefix_4]

        return "未知厂商"

# 初始化MAC厂商数据库
db_path = os.path.join(APP_ROOT, "mac.db")
if os.path.exists(db_path):
    mac_vendor_db = MACVendorDatabase(db_path)
else:
    mac_vendor_db = None
    print(f"MAC database not found at {db_path}")

def check_port(ip, port):
    """检测指定IP的指定端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def ping_ip(ip):
    try:
        # 首先检查ARP表中是否存在该IP，存在则视为存活
        arp_table = get_arp_table(ip)  # 查询单个IP的ARP条目
        if ip in arp_table:
            return True, ip
        
        output = subprocess.check_output(
            f"ping -n 1 -w 500 {ip}",  # 减少ping超时时间到500ms
            shell=True,
            stderr=subprocess.STDOUT,
            text=True
        )

        if "TTL=" in output:
            return True, ip
        else:
            # Ping失败，尝试端口检测
            for port in DETECTION_PORTS:
                if check_port(ip, port):
                    return True, ip
            return False, ip
    except subprocess.CalledProcessError:
        # Ping失败，尝试端口检测
        for port in DETECTION_PORTS:
            if check_port(ip, port):
                return True, ip
        return False, ip
    except Exception:
        return False, ip

def get_local_network_info():
    local_networks = []
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2 and not addr.address.startswith('127.'):
                    ip = addr.address
                    netmask = addr.netmask
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    local_networks.append({
                        'interface': interface,
                        'ip': ip,
                        'netmask': netmask,
                        'network': str(network)
                    })
    except Exception as e:
        print(f"Failed to get local network info: {str(e)}")
    return local_networks

# 缓存本地网络信息
local_networks_cache = None

def is_in_local_network(ip):
    global local_networks_cache
    try:
        # 只获取一次本地网络信息
        if local_networks_cache is None:
            local_networks_cache = get_local_network_info()
        ip_obj = ipaddress.IPv4Address(ip)
        for network_info in local_networks_cache:
            network = ipaddress.IPv4Network(network_info['network'])
            if ip_obj in network:
                return True
        return False
    except Exception:
        return False

def get_arp_table(ip=None):
    arp_table = {}
    try:
        cmd = "arp -a"
        if ip:
            cmd += f" {ip}"  # 查询单个IP的ARP条目，更快
        output = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            encoding="cp437"
        )

        for line in output.split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', line)
            if match:
                ip_addr = match.group(1)
                mac = match.group(2).replace('-', ':')
                arp_table[ip_addr] = mac
    except Exception as e:
        print(f"Failed to get ARP table: {str(e)}")

    return arp_table

def get_hostname(ip):
    try:
        # Shorten timeouts for faster resolution
        socket.setdefaulttimeout(0.5)  # 500ms timeout for DNS resolution
        hostname, aliases, ips = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.timeout):
        try:
            output = subprocess.check_output(
                f"ping -a -n 1 -w 500 {ip}",  # 500ms ping timeout
                shell=True,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="cp437",
                timeout=1  # 1 second total timeout
            )
            
            # 解析ping -a的输出，支持中英文
            match = re.search(r'(?:Pinging|正在 Ping)\s+([^\s\[]+)', output)
            if match:
                hostname = match.group(1).strip()
                # 过滤掉可能的IPv6地址格式
                if hostname.count(':') < 2:
                    return hostname
        except subprocess.CalledProcessError:
            pass
        except Exception:
            pass
    return None

def arp_scan(ip, arp_table=None):
    try:
        logging.debug(f"Starting arp_scan for {ip}")
        success = False
        mac = ""
        vendor = ""
        hostname = ""
        
        # First, always try to ping the IP
        ping_result, _ = ping_ip(ip)
        logging.debug(f"Ping result for {ip}: {ping_result}")
        
        if ping_result:
            success = True
            hostname = get_hostname(ip)  # Resolve hostname
            
            # Check ARP table only if it's a local network IP
            if is_in_local_network(ip):
                # Get ARP entry for this specific IP only
                arp_table = get_arp_table(ip)
                if ip in arp_table:
                    mac = arp_table[ip]
                    vendor = mac_vendor_db.get_vendor(mac) if mac_vendor_db else "Unknown"
                    logging.info(f"Ping succeeded for {ip}: MAC={mac}, Vendor={vendor}, Hostname={hostname}")
                else:
                    logging.debug(f"{ip} not found in ARP table after successful ping")
            else:
                # For non-local IPs, we only need ping result and hostname
                logging.debug(f"Ping successful for non-local IP {ip}, Hostname={hostname}")
        else:
            logging.debug(f"Ping failed for IP {ip}")
        
        return {'success': success, 'mac': mac, 'vendor': vendor, 'hostname': hostname}
    except Exception as e:
        logging.error(f"Error in arp_scan for {ip}: {str(e)}")
        return {'success': False, 'mac': "", 'vendor': "", 'hostname': ""}

def get_ip_list(ip_range):
    try:
        logging.info(f"Parsing IP range: {ip_range}")
        # 支持多段IP地址，使用分号分隔
        ranges = [r.strip() for r in ip_range.split(';') if r.strip()]
        all_ips = []
        
        for single_range in ranges:
            try:
                if '/' in single_range:
                    # CIDR格式
                    network = ipaddress.IPv4Network(single_range)
                    host_list = [str(ip) for ip in network.hosts()]
                    logging.info(f"Parsed CIDR range {single_range} to {len(host_list)} host(s)")
                    all_ips.extend(host_list)
                elif '-' in single_range:
                    # 范围格式
                    start_ip, end_part = single_range.split('-')
                    start_ip = start_ip.strip()
                    end_part = end_part.strip()
                    logging.info(f"Range split: start={start_ip}, end={end_part}")
                    
                    start_parts = list(map(int, start_ip.split('.')))
                    if len(start_parts) != 4:
                        logging.error(f"Invalid start IP format: {start_ip}")
                        continue
                    
                    # 解析结束IP
                    if '.' in end_part:
                        end_parts = list(map(int, end_part.split('.')))
                        if len(end_parts) != 4:
                            logging.error(f"Invalid end IP format: {end_part}")
                            continue
                    else:
                        end_parts = start_parts.copy()
                        end_parts[3] = int(end_part)
                    
                    # 检查IP地址是否有效
                    valid = True
                    for octet in start_parts + end_parts:
                        if octet < 0 or octet > 255:
                            logging.error(f"Invalid octet in IP: {octet}")
                            valid = False
                            break
                    if not valid:
                        continue
                    
                    # 转换为整数以便比较
                    start_int = (start_parts[0] << 24) | (start_parts[1] << 16) | (start_parts[2] << 8) | start_parts[3]
                    end_int = (end_parts[0] << 24) | (end_parts[1] << 16) | (end_parts[2] << 8) | end_parts[3]
                    
                    if start_int > end_int:
                        logging.error("Start IP is greater than end IP in range: {single_range}")
                        continue
                    
                    # 生成IP列表
                    for i in range(start_int, end_int + 1):
                        ip = f"{i >> 24 & 0xFF}.{i >> 16 & 0xFF}.{i >> 8 & 0xFF}.{i & 0xFF}"
                        all_ips.append(ip)
                    logging.info(f"Generated {end_int - start_int + 1} IP address(es) from range {single_range}")
                else:
                    # 单个IP格式
                    ip = ipaddress.IPv4Address(single_range.strip())
                    all_ips.append(str(ip))
                    logging.info(f"Parsed single IP: {str(ip)}")
            except Exception as e:
                logging.error(f"Error parsing single range {single_range}: {e}", exc_info=True)
                continue
        
        # 去重并返回
        unique_ips = list(set(all_ips))
        unique_ips.sort()  # 按IP地址排序
        logging.info(f"Total unique IPs after parsing all ranges: {len(unique_ips)}")
        logging.debug(f"Unique IP list: {unique_ips}")
        return unique_ips
    except Exception as e:
        logging.error(f"Error parsing IP range: {e}", exc_info=True)
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test', methods=['GET'])
def test():
    return jsonify({'status': 'ok', 'message': 'Server is running'})

@app.route('/ping', methods=['POST'])
def ping():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'IP地址不能为空'}), 400

    success, result_ip = ping_ip(ip)
    return jsonify({'success': success, 'ip': result_ip})

@app.route('/export', methods=['POST'])
def export_results():
    data = request.get_json()
    results = data.get('results', [])
    
    if not results:
        return jsonify({'error': 'No results to export'}), 400
    
    # Create Excel workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Ping Scan Results"
    
    # Write header row
    headers = ['IP地址', '状态', '主机名', 'MAC地址', '厂商']
    ws.append(headers)
    
    # Write data rows
    for result in results:
        row = [
            result['ip'],
            result['status'],
            result['hostname'],
            result['mac'],
            result['vendor']
        ]
        ws.append(row)
    
    # Save to BytesIO buffer
    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    
    # Return as response
    return Response(
        buffer,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={
            'Content-Disposition': 'attachment; filename=ping_scan_results.xlsx',
            'Content-Length': str(len(buffer.getvalue()))
        }
    )

@app.route('/preset-ip-ranges', methods=['GET'])
def preset_ip_ranges():
    """获取预置IP段配置"""
    logging.info(f"Returning preset IP ranges: {PRESET_IP_RANGES}")
    return jsonify({'ip_ranges': PRESET_IP_RANGES})

@app.route('/version-check-config', methods=['GET'])
def version_check_config():
    """获取版本检查配置"""
    logging.info(f"Returning version check config: enabled={ENABLE_VERSION_CHECK}, url={VERSION_CHECK_URL}, timeout={VERSION_CHECK_TIMEOUT}, max_attempts={VERSION_CHECK_MAX_ATTEMPTS}")
    return jsonify({
        'enable_version_check': ENABLE_VERSION_CHECK,
        'version_check_url': VERSION_CHECK_URL,
        'version_check_timeout': VERSION_CHECK_TIMEOUT,
        'version_check_max_attempts': VERSION_CHECK_MAX_ATTEMPTS
    })

@app.route('/detection-ports', methods=['GET'])
def detection_ports():
    return jsonify(DETECTION_PORTS)

@app.route('/detection-ports', methods=['POST'])
def update_detection_ports():
    global DETECTION_PORTS
    new_ports = request.json.get('ports', [])
    # Validate ports
    try:
        validated_ports = [int(port) for port in new_ports if 1 <= int(port) <= 65535]
        if not validated_ports:
            return jsonify({'error': 'No valid ports provided'}), 400
        
        # Update the global variable
        DETECTION_PORTS = validated_ports
        
        # Update the config file
        config['Detection']['Ports'] = ','.join(map(str, DETECTION_PORTS))
        with open(config_path, 'w', encoding='utf-8') as f:
            config.write(f)
        
        logging.info(f"Updated detection ports to: {DETECTION_PORTS}")
        return jsonify({'success': True, 'ports': DETECTION_PORTS})
    except (ValueError, KeyError) as e:
        return jsonify({'error': str(e)}), 400

@app.route('/version-check', methods=['GET'])
def version_check():
    """版本检查代理"""
    try:
        logging.info(f"Received /version-check request, proxying to: {VERSION_CHECK_URL}")
        # 向NAS服务器发起请求
        response = requests.get(VERSION_CHECK_URL, timeout=VERSION_CHECK_TIMEOUT)
        # 确保响应状态码为200
        response.raise_for_status()
        logging.info(f"Proxy request successful, status code: {response.status_code}, content: {response.text.strip()}")
        # 返回响应内容
        return Response(response.content, mimetype=response.headers.get('Content-Type', 'text/plain'))
    except Exception as e:
        logging.error(f"版本检查代理错误: {str(e)}")
        # 如果请求失败，返回空响应或错误信息
        return Response('0.0', mimetype='text/plain')

@app.route('/scan', methods=['POST'])

def scan():
    data = request.get_json()
    ip_range = data.get('ip_range')
    concurrency = data.get('concurrency', 100)  # 增加默认并发数到100
    logging.info(f"Received scan request: ip_range={ip_range}, concurrency={concurrency}")

    if not ip_range:
        logging.error("Scan request failed: IP范围不能为空")
        return jsonify({'error': 'IP范围不能为空'}), 400

    ip_list = get_ip_list(ip_range)
    logging.info(f"Generated ip_list: {ip_list}")

    if not ip_list:
        logging.error(f"Scan request failed: 无效的IP范围 - {ip_range}")
        return jsonify({'error': '无效的IP范围'}), 400

    # ARP table will be refreshed individually after each ping in arp_scan
    arp_table = None

    def generate():
        logging.info(f"Starting concurrent scan with {concurrency} workers")
        # 首先发送总数量信息
        total_message = {
            'type': 'total',
            'total': len(ip_list)
        }
        yield f"data: {json.dumps(total_message)}\n\n"
        
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_ip = {executor.submit(arp_scan, ip, arp_table): ip for ip in ip_list}
            # 使用as_completed()更快返回完成的结果
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                result_data = future.result()
                logging.info(f"Scan result for {ip}: {result_data}")
                # 生成扫描结果消息
                scan_result = {
                    'type': 'result',
                    'ip': ip,
                    'success': result_data['success'],
                    'mac': result_data['mac'],
                    'vendor': result_data['vendor'],
                    'hostname': result_data['hostname']
                }
                yield f"data: {json.dumps(scan_result)}\n\n"

    # 返回SSE响应，设置适当的内容类型
    return Response(generate(), mimetype='text/event-stream')

def open_browser():
    # Wait for the server to start
    time.sleep(2)
    # Open the browser to the application URL
    webbrowser.open('http://localhost:5000/')

if __name__ == '__main__':
    # Check if running in the main process (not the reloader)
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        # Start browser in a separate thread after a short delay
        threading.Timer(2.0, webbrowser.open, args=(f'http://localhost:{WEB_SERVER_PORT}/',)).start()
    # Run Flask app
    app.run(debug=False, host='0.0.0.0', port=WEB_SERVER_PORT)