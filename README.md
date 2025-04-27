# Reimu_Crawler_Toolbox
本项目是一个基于 Flask 的Python爬虫工具箱，集成了以下实用功能：

- **cURL 转 Python**：将 cURL 命令一键转换为 Python requests 代码。
- **请求头格式化**：将原始 HTTP 请求头格式化为 JSON 格式。
- **UA 生成器**：根据设备类型随机生成 User-Agent 字符串。
- **IP 信息查询**：展示客户端 IP 及请求相关信息。

未来还会继续增加功能

如果你感到满意，可以点个 star 支持一下

## 网页效果
[https://reimucrawlertoolbox.mydreamship.org/](https://reimucrawlertoolbox.mydreamship.org/)
## 项目结构

```
├── app.py                
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

## 安装与运行

1. 安装依赖：

```bash
pip install -r requirements.txt
```

2. 启动服务：

```bash
python app.py
```

默认监听端口为 `4303`，可通过浏览器访问 `http://localhost:4303`。

## 功能说明

### 1. cURL 转 Python
- 路径：`/curl-to-python`
- 输入 cURL 命令，自动转换为 Python requests 代码。

### 2. 请求头格式化
- 路径：`/header-formatter`
- 输入原始请求头文本，输出格式化后的 JSON。

### 3. UA 生成器
- 路径：`/ua-generator`
- 支持桌面和移动设备类型，生成随机 User-Agent。

### 4. IP 信息查询
- 路径：`/ip-info`
- 展示访问者的 IP 及请求相关信息。

## 依赖环境
- Python 3.7+
- Flask==2.3.2
- user-agents==2.2.0

## 许可证（License）

本项目采用 MIT License，并附加如下声明：

- 允许二次创作和商用，但必须在显著位置保留原作者信息。
- 原作者信息：
  - 作者：Itz_Reimu
  - 项目地址：https://github.com/ItzReimu/Reimu_Crawler_Toolbox/
  - 
如需二次开发或引用，请遵守以上条款。
