# Reimu Crawler Toolbox 

## 项目简介

Reimu Crawler Toolbox 是一个爬虫辅助工具，基于 Flask 构建，提供多种实用功能，帮助开发者简化网络请求和数据抓取工作。

## 主要功能

- **cURL 转 Python**：将 cURL 命令一键转换为 Python requests 代码
- **请求头格式化**：将原始 HTTP 请求头转换为标准 JSON 格式
- **UA 生成器**：智能生成设备类型的 User-Agent 字符串
- **IP 信息查询**：展示客户端 IP 和详细请求信息
- **解码工具**：支持多种编码、加密、base64、url加密、凯撒密码等自动识别与解码
- **时间戳转换工具**：支持日期时间与时间戳的相互转换

## 项目特点

- 简单易用的 Web 界面
- 开源且持续更新
- 轻量级网络开发工具集 Python 工具集

## 项目结构

```
Reimu_Crawler_Toolbox/
├── app.py                
├── decode.py            
├── requirements.txt      
├── static/              
├── templates/            
│   ├── base.html
│   ├── curl_to_python.html
│   ├── header_formatter.html
│   ├── index.html
│   ├── ip_info.html
│   └── ua_generator.html
```

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/ItzReimu/Reimu_Crawler_Toolbox.git
cd Reimu_Crawler_Toolbox
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 启动服务

```bash
python app.py
```

🌐 默认访问地址：`http://localhost:4303`

## 在线演示

[Reimu Crawler Toolbox](https://reimucrawlertoolbox.mydreamship.org/)

## 贡献与支持

- 欢迎 Star ⭐
- 提交 Issue 或 Pull Request
- 分享你的使用体验

## 许可证

MIT License

## 联系方式

如有任何问题，请联系项目作者。


## 依赖环境 🛠️
- 推荐Python3.10+
- 相关第三方包
```
Flask==3.1.0
user-agents==2.2.0
pycryptodome==3.22.0
base58==2.1.1
requests==2.32.3
Werkzeug==3.1.3
PyJWT==2.10.1
```


## 功能详细说明 🔍

### 1. cURL 转 Python
- **路径**：`/curl-to-python`
- **功能**：输入 cURL 命令，自动转换为 Python requests 代码。

### 2. 请求头格式化
- **路径**：`/header-formatter`
- **功能**：输入原始请求头文本，输出格式化后的 JSON。

### 3. UA 生成器
- **路径**：`/ua-generator`
- **功能**：支持桌面和移动设备类型，生成随机 User-Agent。

### 4. IP 信息查询
- **路径**：`/ip-info`
- **功能**：展示访问者的 IP 及请求相关信息。

### 5. 解码工具
- **路径**：`/decode`
- **功能**：支持 Base64、URL、HTML、Hex、二进制、八进制、摩斯电码、ROT13、哈希、加密等多种编码/加密/哈希/压缩方式的自动识别与解码

### 6. 时间戳转换工具
- **路径**：`/timestamp`
- **功能**：支持日期时间与时间戳的相互转换，自动识别毫秒/秒，支持 ISO 格式输入。

## 许可证（License）🔒

本项目采用 MIT License，并附加如下声明：

- 允许二次创作和商用
- 必须在显著位置保留原作者信息
- 鼓励开放和创新

### 原作者信息
- **作者**: Itz_Reimu
- **项目地址**: [Reimu_Crawler_Toolbox](https://github.com/ItzReimu/Reimu_Crawler_Toolbox/)

如需二次开发或引用，请遵守以上条款。
