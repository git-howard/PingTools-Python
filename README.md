# PingToolsHTML5

一个基于Web的网络工具，用于IP扫描、Ping检测、端口扫描等功能。

## 功能

- **IP范围扫描**：支持批量扫描指定IP范围内的所有IP
- **Ping检测**：检测IP是否可达（支持ICMP Ping）
- **ARP表检查**：如果IP在ARP表中，则直接视为存活
- **端口检测**：Ping失败时自动检测配置的TCP端口
- **结果导出**：支持将扫描结果导出为Excel文件
- **版本检查**：自动检测新版本并提示下载

## 安装

### 环境要求

- Python 3.6+ 
- Flask
- psutil
- openpyxl
- 其他依赖见requirements.txt

### 安装步骤

1. 安装依赖：

```bash
pip install -r requirements.txt
```

2. 运行应用：

```bash
python app.py
```

3. 打开浏览器访问：`http://localhost:5000`

## 使用

1. 在首页输入IP范围（例如：192.168.1.1-192.168.1.255）
2. 点击"开始扫描"按钮
3. 等待扫描完成，查看结果
4. 点击"导出Excel"按钮保存结果

## 配置

配置文件位于`web/config.ini`，可修改以下参数：

### Detection部分

- **Ports**：配置需要检测的TCP端口（逗号分隔）

```ini
[Detection]
Ports = 22,80,443,3389,1433,5000
```

## 项目结构

```
PingToolsHTML5/
├── web/
│   ├── app.py              # 主应用程序
│   ├── config.ini          # 配置文件
│   ├── mac.db              # MAC厂商数据库
│   ├── requirements.txt    # 依赖列表
│   ├── static/            # 静态资源
│   └── templates/         # HTML模板
└── README.md              # 项目说明
```

## 注意事项

- 本项目使用Flask开发服务器，仅适用于测试环境
- 端口检测功能可能会被防火墙拦截，请确保相关端口允许访问
- ARP表检查仅适用于本地网络
- 版本检查功能需要网络连接以获取最新版本信息

## 版本

当前版本：0.2