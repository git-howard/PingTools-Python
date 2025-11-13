import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import subprocess
import ipaddress
import socket
import re
import psutil
import configparser
import os
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3

class MACVendorDatabase:
    def __init__(self, db_path=None):
        self.vendor_dict = {}
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), "mac.db")
        self.load_data()
    
    def load_data(self):
        """加载MAC厂商信息"""
        try:
            self.load_from_database()
        except Exception as e:
            print(f"从数据库加载失败: {str(e)}")
    
    def load_from_database(self):
        """从SQLite数据库加载MAC厂商信息"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM mac")
            rows = cursor.fetchall()
            
            # 直接使用表结构，因为我们已经知道mac表的结构
            # assignment在第2列（索引1），organization_name在第3列（索引2）
            for row in rows:
                if len(row) >= 3:
                    mac_prefix = str(row[1]).upper().strip()  # assignment列
                    vendor_name = str(row[2]).strip()  # organization_name列
                    if mac_prefix and vendor_name:
                        self.vendor_dict[mac_prefix] = vendor_name
            
            conn.close()
        except Exception as e:
            raise Exception(f"数据库加载失败: {str(e)}")
    
    def get_vendor(self, mac_address):
        """获取MAC地址对应的厂商信息"""
        # 清理MAC地址，移除所有非十六进制字符
        clean_mac = ''.join(c for c in mac_address.upper() if c in '0123456789ABCDEF')
        
        # 确保MAC地址有效
        if len(clean_mac) < 6:
            return "未知厂商"
        
        # 尝试不同长度的前缀匹配
        # 首先尝试6位前缀（24位）
        prefix_6 = clean_mac[:6]
        if prefix_6 in self.vendor_dict:
            return self.vendor_dict[prefix_6]
        
        # 然后尝试5位前缀（20位）
        prefix_5 = clean_mac[:5]
        if prefix_5 in self.vendor_dict:
            return self.vendor_dict[prefix_5]
        
        # 最后尝试4位前缀（16位）
        prefix_4 = clean_mac[:4]
        if prefix_4 in self.vendor_dict:
            return self.vendor_dict[prefix_4]
        
        return "未知厂商"
    
    def __len__(self):
        """返回已加载的MAC厂商信息数量"""
        return len(self.vendor_dict)
    
    def __contains__(self, mac_prefix):
        """检查MAC前缀是否存在于数据库中"""
        return mac_prefix.upper() in self.vendor_dict
    
    def list_vendors(self, limit=100):
        """列出部分厂商信息"""
        return list(self.vendor_dict.items())[:limit]

class PingTool:
    def __init__(self, root):
        self.root = root
        self.root.title("网络Ping扫描工具")
        self.root.geometry("1000x750")
        self.root.configure(bg="#f0f0f0")
        
        # 设置窗口图标
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass  # 如果图标文件不存在，忽略错误
        
        # 设置主题颜色
        self.bg_color = "#f0f0f0"
        self.primary_color = "#3498db"
        self.success_color = "#2ecc71"
        self.danger_color = "#e74c3c"
        self.warning_color = "#f39c12"
        self.text_color = "#2c3e50"
        self.card_bg = "#ffffff"
        
        # 创建样式
        self.setup_styles()
        
        # 初始化变量
        self.ip_range_var = tk.StringVar()
        self.concurrency_var = tk.IntVar(value=50)
        self.is_scanning = False
        self.ip_widgets = []
        self.config_file = "ping_tool_config.ini"
        self.ip_mac_map = {}  # 存储IP和MAC地址的映射
        self.local_networks = []  # 存储本地网络信息
        self.cols_per_row = 16  # 每行显示的IP数量，默认为16
        self.mac_vendor_db = MACVendorDatabase()  # MAC厂商数据库实例
        
        # 创建界面
        self.create_widgets()
        
        # 加载配置
        self.load_config()
        
        # 绑定窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_styles(self):
        """设置ttk样式"""
        self.style = ttk.Style()
        
        # 设置按钮样式
        self.style.configure("Primary.TButton", 
                           background=self.primary_color,
                           foreground=self.text_color,
                           borderwidth=0,
                           focuscolor="none",
                           font=("Microsoft YaHei UI", 9, "bold"))
        
        self.style.map("Primary.TButton",
                      background=[("active", "#2980b9")])
        
        self.style.configure("Success.TButton",
                           background=self.success_color,
                           foreground=self.text_color,
                           borderwidth=0,
                           focuscolor="none",
                           font=("Microsoft YaHei UI", 9, "bold"))
        
        self.style.map("Success.TButton",
                      background=[("active", "#27ae60")])
        
        self.style.configure("Danger.TButton", 
                           background=self.danger_color,
                           foreground=self.text_color,
                           borderwidth=0,
                           focuscolor="none",
                           font=("Microsoft YaHei UI", 9, "bold"))
        
        self.style.map("Danger.TButton",
                      background=[("active", "#c0392b")])
        
        self.style.configure("Warning.TButton",
                           background=self.warning_color,
                           foreground=self.text_color,
                           borderwidth=0,
                           focuscolor="none",
                           font=("Microsoft YaHei UI", 9, "bold"))
        
        self.style.map("Warning.TButton",
                      background=[("active", "#f39c12")])
        
        self.style.configure("Info.TButton",
                           background="#3498db",
                           foreground=self.text_color,
                           borderwidth=0,
                           focuscolor="none",
                           font=("Microsoft YaHei UI", 9, "bold"))
        
        self.style.map("Info.TButton",
                      background=[("active", "#2980b9")])
        
        # 设置标签框架样式
        self.style.configure("Card.TLabelframe", 
                           background=self.card_bg,
                           borderwidth=1,
                           relief="solid")
        
        self.style.configure("Card.TLabelframe.Label", 
                           background=self.card_bg,
                           foreground=self.text_color,
                           font=("Microsoft YaHei UI", 10, "bold"))
        
        # 设置进度条样式
        self.style.configure("TProgressbar",
                           troughcolor="#e0e0e0",
                           background=self.primary_color,
                           borderwidth=0,
                           lightcolor=self.primary_color,
                           darkcolor=self.primary_color)
    
    def create_widgets(self):
        # 创建菜单栏
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)
        
        # 创建帮助菜单
        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)
        
        # 顶部控制区域
        control_frame = ttk.LabelFrame(self.root, text="扫描设置", padding="15", style="Card.TLabelframe")
        control_frame.pack(fill=tk.X, padx=15, pady=10)
        
        # 第一行：IP范围输入
        ip_frame = tk.Frame(control_frame, bg=self.card_bg)
        ip_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(ip_frame, text="IP范围:", bg=self.card_bg, fg=self.text_color, 
                font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.ip_entry = tk.Entry(ip_frame, textvariable=self.ip_range_var, width=30, 
                                font=("Microsoft YaHei UI", 10), relief="solid", bd=1)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        # 添加提示文本
        self.ip_entry.insert(0, "例如: 192.168.1.1-192.168.1.254 或 192.168.1.0/24")
        self.ip_entry.config(fg="#999999")
        self.ip_entry.bind("<FocusIn>", self.on_entry_focus_in)
        self.ip_entry.bind("<FocusOut>", self.on_entry_focus_out)
        

        
        # 第二行：并发量和按钮
        settings_frame = tk.Frame(control_frame, bg=self.card_bg)
        settings_frame.pack(fill=tk.X, pady=10)
        
        # 并发量设置
        tk.Label(settings_frame, text="并发量:", bg=self.card_bg, fg=self.text_color,
                font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.concurrency_spinbox = tk.Spinbox(settings_frame, from_=1, to=200, 
                                             textvariable=self.concurrency_var, width=10,
                                             font=("Microsoft YaHei UI", 10), 
                                             relief="solid", bd=1)
        self.concurrency_spinbox.pack(side=tk.LEFT, padx=5)
        
        tk.Label(settings_frame, text="(1-200)", bg=self.card_bg, fg="#666666",
                font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=5)
        
        # 按钮区域
        button_frame = tk.Frame(settings_frame, bg=self.card_bg)
        button_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        # 左侧按钮
        left_button_frame = tk.Frame(button_frame, bg=self.card_bg)
        left_button_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.start_button = ttk.Button(left_button_frame, text="开始扫描", 
                                      command=self.start_scan, 
                                      style="Primary.TButton")
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(left_button_frame, text="停止扫描", 
                                    command=self.stop_scan, 
                                    style="Danger.TButton", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # 右侧按钮
        right_button_frame = tk.Frame(button_frame, bg=self.card_bg)
        right_button_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        

        
        self.clear_btn = ttk.Button(right_button_frame, text="清空结果", 
                                  command=self.clear_results, 
                                  style="Primary.TButton")
        self.clear_btn.pack(side=tk.RIGHT, padx=5)
        
        self.save_btn = ttk.Button(right_button_frame, text="保存结果", 
                                 command=self.save_results, 
                                 style="Primary.TButton")
        self.save_btn.pack(side=tk.RIGHT, padx=5)
        
        # 进度条区域
        progress_frame = tk.Frame(self.root, bg=self.bg_color)
        progress_frame.pack(fill=tk.X, padx=15, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                          maximum=100, length=970, 
                                          style="TProgressbar")
        self.progress_bar.pack(fill=tk.X)
        
        # 状态标签
        status_frame = tk.Frame(self.root, bg=self.bg_color)
        status_frame.pack(fill=tk.X, padx=15, pady=5)
        
        self.status_var = tk.StringVar(value="就绪")
        self.status_label = tk.Label(status_frame, textvariable=self.status_var, bg=self.bg_color, 
                                    fg=self.text_color, font=("Microsoft YaHei UI", 9))
        self.status_label.pack(side=tk.LEFT)
        
        self.time_label = tk.Label(status_frame, text="", bg=self.bg_color, 
                                  fg="#666666", font=("Microsoft YaHei UI", 9))
        self.time_label.pack(side=tk.RIGHT)
        
        # 结果汇总区域
        summary_frame = ttk.LabelFrame(self.root, text="扫描结果汇总", padding="10", 
                                     style="Card.TLabelframe")
        summary_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.total_var = tk.StringVar(value="总IP数: 0")
        ttk.Label(summary_frame, textvariable=self.total_var).pack(side=tk.LEFT, padx=10)
        
        self.success_var = tk.StringVar(value="在线: 0")
        ttk.Label(summary_frame, textvariable=self.success_var).pack(side=tk.LEFT, padx=10)
        
        self.failed_var = tk.StringVar(value="离线: 0")
        ttk.Label(summary_frame, textvariable=self.failed_var).pack(side=tk.LEFT, padx=10)
        
        self.pending_var = tk.StringVar(value="待扫描: 0")
        ttk.Label(summary_frame, textvariable=self.pending_var).pack(side=tk.LEFT, padx=10)
        
        # IP显示区域
        ip_frame = ttk.LabelFrame(self.root, text="IP地址状态", padding="10", 
                                 style="Card.TLabelframe")
        ip_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        # 创建滚动区域
        canvas = tk.Canvas(ip_frame, bg=self.card_bg, highlightthickness=0)
        scrollbar = ttk.Scrollbar(ip_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg=self.card_bg)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 绑定鼠标滚轮事件
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)  # Windows
        
        # 绑定窗口大小变化事件
        self.root.bind("<Configure>", self.on_window_resize)
    
    def on_entry_focus_in(self, event):
        """输入框获得焦点时清除提示文本"""
        if self.ip_entry.get() == "例如: 192.168.1.1-192.168.1.254 或 192.168.1.0/24":
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.config(fg="#000000")
    
    def on_entry_focus_out(self, event):
        """输入框失去焦点时恢复提示文本"""
        if not self.ip_entry.get():
            self.ip_entry.insert(0, "例如: 192.168.1.1-192.168.1.254 或 192.168.1.0/24")
            self.ip_entry.config(fg="#999999")
    
    def on_window_resize(self, event):
        """窗口大小变化事件处理"""
        # 只在窗口大小变化时重新布局IP格子
        if event.widget == self.root and self.ip_widgets:
            # 保存当前IP列表
            ip_list = [widget_info['ip'] for widget_info in self.ip_widgets]
            
            # 重新创建IP控件
            self.create_ip_widgets(ip_list)
    
    def parse_ip_range(self, ip_range):
        
        try:
            # 处理CIDR格式 (例如: 192.168.1.0/24)
            if '/' in ip_range:
                network = ipaddress.ip_network(ip_range, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            
            # 处理IP范围格式 (例如: 192.168.1.1-192.168.1.100)
            elif '-' in ip_range:
                start_ip, end_ip = ip_range.split('-')
                start_ip = start_ip.strip()
                end_ip = end_ip.strip()
                
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
                
                for ip_int in range(int(start), int(end) + 1):
                    ip_list.append(str(ipaddress.IPv4Address(ip_int)))
            
            # 处理单个IP
            else:
                ipaddress.IPv4Address(ip_range)  # 验证IP格式
                ip_list = [ip_range]
                
        except Exception as e:
            messagebox.showerror("错误", f"IP范围格式错误: {str(e)}")
            return None
            
        return ip_list
    
    def ping_ip(self, ip):
        """Ping单个IP地址"""
        try:
            # Windows系统使用ping命令
            output = subprocess.check_output(
                f"ping -n 1 -w 1000 {ip}",
                shell=True,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # 检查是否包含"TTL="来判断是否ping通
            if "TTL=" in output:
                return True, ip
            else:
                return False, ip
                
        except subprocess.CalledProcessError:
            return False, ip
        except Exception:
            return False, ip
    
    def get_local_network_info(self):
        """获取本地网络信息"""
        try:
            # 获取所有网络接口
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    # 只处理IPv4地址
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        ip = addr.address
                        netmask = addr.netmask
                        
                        # 计算网络地址
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        self.local_networks.append({
                            'interface': interface,
                            'ip': ip,
                            'netmask': netmask,
                            'network': str(network)
                        })
        except Exception as e:
            print(f"获取本地网络信息失败: {str(e)}")
    
    def is_in_local_network(self, ip):
        """检查IP是否在本地网络中"""
        try:
            # 如果本地网络信息为空，则获取本地网络信息
            if not self.local_networks:
                self.get_local_network_info()
            
            ip_obj = ipaddress.IPv4Address(ip)
            for network_info in self.local_networks:
                network = ipaddress.IPv4Network(network_info['network'])
                if ip_obj in network:
                    return True
            return False
        except Exception:
            return False
    
    def get_arp_table(self):
        """获取ARP表"""
        arp_table = {}
        try:
            # Windows系统使用arp -a命令
            output = subprocess.check_output(
                "arp -a",
                shell=True,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # 解析ARP表
            for line in output.split('\n'):
                # 匹配IP和MAC地址的正则表达式
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':')  # 将MAC地址格式化为标准格式
                    arp_table[ip] = mac
        except Exception as e:
            print(f"获取ARP表失败: {str(e)}")
        
        return arp_table
    
    def arp_scan(self, ip):
        """使用ARP扫描检测IP是否在线"""
        # 如果IP不在本地网络，使用普通ping
        if not self.is_in_local_network(ip):
            return self.ping_ip(ip)
        
        # 对于本地网络，尝试获取ARP信息
        arp_table = self.get_arp_table()
        
        # 如果ARP表中已有该IP的记录
        if ip in arp_table:
            mac = arp_table[ip]
            self.ip_mac_map[ip] = mac
            return True, ip
        
        # 尝试ping以触发ARP请求
        try:
            subprocess.check_output(
                f"ping -n 1 -w 500 {ip}",
                shell=True,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # 再次获取ARP表
            arp_table = self.get_arp_table()
            if ip in arp_table:
                mac = arp_table[ip]
                self.ip_mac_map[ip] = mac
                return True, ip
            else:
                return False, ip
        except subprocess.CalledProcessError:
            return False, ip
        except Exception:
            return False, ip
    
    def update_ip_widget(self, ip, status):
        """更新IP地址显示状态"""
        for widget_info in self.ip_widgets:
            if widget_info['ip'] == ip:
                if status == 'success':
                    widget_info['widget'].configure(bg=self.success_color, fg='white')
                elif status == 'failed':
                    widget_info['widget'].configure(bg=self.danger_color, fg='white')
                elif status == 'scanning':
                    widget_info['widget'].configure(bg=self.warning_color, fg='white')
                break
    
    def scan_worker(self, ip_list, result_queue):
        """扫描工作线程"""
        total = len(ip_list)
        success_count = 0
        failed_count = 0
        
        with ThreadPoolExecutor(max_workers=self.concurrency_var.get()) as executor:
            # 提交所有任务，使用arp_scan而不是ping_ip
            future_to_ip = {executor.submit(self.arp_scan, ip): ip for ip in ip_list}
            
            for future in as_completed(future_to_ip):
                if not self.is_scanning:
                    break
                    
                ip = future_to_ip[future]
                try:
                    success, result_ip = future.result()
                    if success:
                        success_count += 1
                        result_queue.put(('success', result_ip))
                    else:
                        failed_count += 1
                        result_queue.put(('failed', result_ip))
                except Exception:
                    failed_count += 1
                    result_queue.put(('failed', ip))
                
                # 更新进度
                completed = success_count + failed_count
                progress = (completed / total) * 100
                self.progress_var.set(progress)
                
                # 更新汇总
                self.total_var.set(f"总IP数: {total}")
                self.success_var.set(f"在线: {success_count}")
                self.failed_var.set(f"离线: {failed_count}")
                self.pending_var.set(f"待扫描: {total - completed}")
        
        # 发送扫描完成信号
        result_queue.put(('scan_complete', None))
    
    def process_results(self, result_queue):
        """处理扫描结果"""
        while self.is_scanning:
            try:
                status, ip = result_queue.get(timeout=0.1)
                if status == 'scan_complete':
                    # 扫描完成，更新UI状态
                    self.is_scanning = False
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.status_var.set("扫描完成")
                    break
                else:
                    self.update_ip_widget(ip, status)
            except queue.Empty:
                continue
    
    def create_ip_widgets(self, ip_list):
        """创建IP地址显示控件"""
        # 清除现有控件
        for widget_info in self.ip_widgets:
            widget_info['widget'].destroy()
        self.ip_widgets.clear()
        
        # 固定每行显示25个IP
        self.cols_per_row = 25
        
        # 计算需要的行数
        rows = (len(ip_list) + self.cols_per_row - 1) // self.cols_per_row
        
        # 创建控件
        for i, ip in enumerate(ip_list):
            row = i // self.cols_per_row
            col = i % self.cols_per_row
            
            # 创建标签
            label = tk.Label(
                self.scrollable_frame,
                text=ip.split('.')[-1],  # 只显示IP的最后一段
                bg='#e0e0e0',
                fg=self.text_color,
                width=4,
                height=2,
                relief=tk.RAISED,
                bd=1,
                font=("Microsoft YaHei UI", 9)
            )
            label.grid(row=row, column=col, padx=1, pady=1)
            
            # 添加工具提示
            self.create_tooltip(label, ip)
            
            # 保存引用
            self.ip_widgets.append({
                'ip': ip,
                'widget': label
            })
    
    def create_tooltip(self, widget, ip):
        """创建工具提示"""
        def on_enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            
            # 构建提示文本
            tooltip_text = f"IP: {ip}"
            if ip in self.ip_mac_map:
                mac = self.ip_mac_map[ip]
                tooltip_text += f"\nMAC: {mac}"
                
                # 获取MAC厂商信息
                try:
                    vendor = self.mac_vendor_db.get_vendor(mac)
                    if vendor:
                        tooltip_text += f"\n厂商: {vendor}"
                except Exception:
                    pass
            
            label = tk.Label(
                tooltip, 
                text=tooltip_text, 
                background="#333333", 
                foreground="white", 
                relief=tk.SOLID, 
                borderwidth=0,
                font=("Microsoft YaHei UI", 9),
                justify=tk.LEFT,
                padx=8,
                pady=5
            )
            label.pack()
            widget.tooltip = tooltip
        
        def on_leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                del widget.tooltip
        
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)
    
    def start_scan(self):
        """开始扫描"""
        ip_range = self.ip_range_var.get().strip()
        if not ip_range:
            messagebox.showwarning("警告", "请输入IP范围或网段")
            return
        
        # 解析IP范围
        ip_list = self.parse_ip_range(ip_range)
        if not ip_list:
            return
        
        # 保存配置
        self.save_config()
        
        # 创建IP显示控件
        self.create_ip_widgets(ip_list)
        
        # 更新UI状态
        self.is_scanning = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("正在扫描...")
        
        # 创建结果队列
        result_queue = queue.Queue()
        
        # 启动扫描线程
        scan_thread = threading.Thread(
            target=self.scan_worker,
            args=(ip_list, result_queue)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        # 启动结果处理线程
        process_thread = threading.Thread(
            target=self.process_results,
            args=(result_queue,)
        )
        process_thread.daemon = True
        process_thread.start()
    
    def stop_scan(self):
        """停止扫描"""
        self.is_scanning = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("扫描已停止")
    
    def clear_results(self):
        """清空扫描结果"""
        # 清除IP显示控件
        for widget_info in self.ip_widgets:
            widget_info['widget'].destroy()
        self.ip_widgets.clear()
        
        # 重置进度条
        self.progress_var.set(0)
        
        # 重置状态标签
        self.status_var.set("就绪")
        self.time_label.config(text="")
        
        # 重置汇总信息
        self.total_var.set("总IP数: 0")
        self.success_var.set("在线: 0")
        self.failed_var.set("离线: 0")
        self.pending_var.set("待扫描: 0")
        
        # 清空IP-MAC映射
        self.ip_mac_map.clear()
    
    def save_results(self):
        """保存扫描结果到文件"""
        if not self.ip_widgets:
            messagebox.showwarning("警告", "没有扫描结果可保存")
            return
        
        # 获取保存文件路径
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="保存扫描结果"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("网络Ping扫描结果\n")
                f.write("=" * 50 + "\n")
                f.write(f"扫描时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"IP范围: {self.ip_range_var.get()}\n")
                f.write("=" * 50 + "\n\n")
                
                # 分类统计在线和离线的IP
                online_ips = []
                offline_ips = []
                
                for widget_info in self.ip_widgets:
                    ip = widget_info['ip']
                    bg_color = widget_info['widget'].cget('bg')
                    
                    if bg_color == self.success_color:
                        online_ips.append(ip)
                    elif bg_color == self.danger_color:
                        offline_ips.append(ip)
                
                # 写入在线IP
                f.write(f"在线IP ({len(online_ips)}个):\n")
                f.write("-" * 30 + "\n")
                for ip in online_ips:
                    f.write(f"  {ip}")
                    if ip in self.ip_mac_map:
                        mac = self.ip_mac_map[ip]
                        f.write(f" - MAC: {mac}")
                        try:
                            vendor = self.mac_vendor_db.get_vendor(mac)
                            if vendor:
                                f.write(f" ({vendor})")
                        except Exception:
                            pass
                    f.write("\n")
                
                f.write("\n")
                
                # 写入离线IP
                f.write(f"离线IP ({len(offline_ips)}个):\n")
                f.write("-" * 30 + "\n")
                for ip in offline_ips:
                    f.write(f"  {ip}\n")
                
                f.write("\n")
                f.write("=" * 50 + "\n")
                f.write(f"总计: {len(self.ip_widgets)}个IP, 在线: {len(online_ips)}个, 离线: {len(offline_ips)}个\n")
            
            messagebox.showinfo("成功", f"扫描结果已保存到:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("错误", f"保存文件失败:\n{str(e)}")
    
    def save_config(self):
        """保存配置到INI文件"""
        config = configparser.ConfigParser()
        config['Settings'] = {
            'ip_range': self.ip_range_var.get(),
            'concurrency': self.concurrency_var.get()
        }
        
        with open(self.config_file, 'w') as f:
            config.write(f)
    
    def load_config(self):
        """从INI文件加载配置"""
        if os.path.exists(self.config_file):
            config = configparser.ConfigParser()
            config.read(self.config_file)
            
            if 'Settings' in config:
                self.ip_range_var.set(config['Settings'].get('ip_range', ''))
                self.concurrency_var.set(config['Settings'].getint('concurrency', 50))
    
    def show_about(self):
        """显示关于信息"""
        # 创建关于窗口
        about_window = tk.Toplevel(self.root)
        about_window.title("关于")
        about_window.geometry("350x150")
        about_window.resizable(False, False)
        
        # 创建标签
        title_label = ttk.Label(about_window, text="网络Ping扫描工具", font=("Helvetica", 14, "bold"))
        title_label.pack(pady=10)
        
        version_label = ttk.Label(about_window, text="版本：1.0")
        version_label.pack(pady=5)
        
        # 创建更新地址超链接
        link_label = ttk.Label(about_window, text="更新地址：https://github.com/git-howard/PingTools-Python", 
                               foreground="blue", cursor="hand2")
        link_label.pack(pady=10)
        
        # 绑定超链接事件
        def open_link(event):
            import webbrowser
            webbrowser.open_new("https://github.com/git-howard/PingTools-Python")
        
        link_label.bind("<Button-1>", open_link)
    
    def on_closing(self):
        """窗口关闭事件"""
        self.save_config()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PingTool(root)
    root.mainloop()