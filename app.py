from flask import Flask, render_template, request, jsonify
import re
import json
from user_agents import parse
import random

app = Flask(__name__)

# 首页
@app.route('/')
def index():
    return render_template('index.html')

# cURL转Python
@app.route('/curl-to-python', methods=['GET', 'POST'])
def curl_to_python():
    if request.method == 'POST':
        curl_command = request.form.get('curl_command', '')
        python_code = convert_curl_to_python(curl_command)
        return jsonify({'python_code': python_code})
    return render_template('curl_to_python.html')

# 请求头格式化
@app.route('/header-formatter', methods=['GET', 'POST'])
def header_formatter():
    if request.method == 'POST':
        raw_headers = request.form.get('raw_headers', '')
        formatted_headers = format_headers(raw_headers)
        return jsonify({'formatted_headers': formatted_headers})
    return render_template('header_formatter.html')

# UA生成器
@app.route('/ua-generator', methods=['GET', 'POST'])
def ua_generator():
    if request.method == 'POST':
        device_type = request.form.get('device_type', 'desktop')
        template_index = request.form.get('template_index')
        ua = generate_user_agent(device_type, template_index)
        return jsonify({'user_agent': ua})
    return render_template('ua_generator.html')

@app.route('/ua-templates', methods=['GET'])
def ua_templates():
    device_type = request.args.get('device_type', 'desktop')
    templates = get_ua_templates(device_type)
    # 返回模板字符串和索引
    return jsonify({'templates': [
        {'index': i, 'template': t} for i, t in enumerate(templates)
    ]})

# 功能实现函数
def convert_curl_to_python(curl_command):
    try:
        # 提取URL
        url_match = re.search(r"curl\s+['\"]([^'\"]+)['\"]", curl_command)
        if not url_match:
            url_match = re.search(r"curl\s+([^\s]+)", curl_command)
        url = url_match.group(1) if url_match else "'<URL>'"
        
        # 提取请求方法
        method = 'GET'
        method_match = re.search(r"-X\s+(\w+)", curl_command)
        if method_match:
            method = method_match.group(1).upper()
        
        # 提取headers
        headers = {}
        header_matches = re.finditer(r"-H\s+['\"]([^'\"]+)['\"]", curl_command)
        for match in header_matches:
            header = match.group(1)
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # 提取data
        data = None
        data_match = re.search(r"--data-raw\s+['\"]([^'\"]+)['\"]", curl_command)
        if not data_match:
            data_match = re.search(r"-d\s+['\"]([^'\"]+)['\"]", curl_command)
        if data_match:
            data = data_match.group(1)
        
        # 生成Python代码
        code = "import requests\n\n"
        code += f"url = '{url}'\n"
        code += f"method = '{method}'\n"
        
        if headers:
            code += "headers = {\n"
            for key, value in headers.items():
                code += f"    '{key}': '{value}',\n"
            code += "}\n"
        else:
            code += "headers = {}\n"
        
        if data:
            code += f"data = '{data}'\n"
        
        code += "\nresponse = requests.request(\n"
        code += "    method=method,\n"
        code += "    url=url,\n"
        if headers:
            code += "    headers=headers,\n"
        if data and method in ['POST', 'PUT', 'PATCH']:
            code += "    data=data,\n"
        code += ")\n\n"
        code += "print(response.text)"
        
        return code
    except Exception as e:
        return f"# 转换出错: {str(e)}\n# 原始cURL命令: {curl_command}"

def format_headers(raw_headers):
    try:
        headers = {}
        lines = raw_headers.strip().split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return json.dumps(headers, indent=4)
    except Exception as e:
        return f"格式化出错: {str(e)}"

def get_ua_templates(device_type):
    desktop_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.0.{1}.{2} Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{0}.{1}) Gecko/20100101 Firefox/{0}.{1}',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{0}_{1}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{2}.0.{3}.{4} Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{0}_{1}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{2}.{3} Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.0.{1}.{2} Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64; rv:{0}.{1}) Gecko/20100101 Firefox/{0}.{1}'
    ]
    mobile_agents = [
        'Mozilla/5.0 (iPhone; CPU iPhone OS {0}_{1} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{2}.{3} Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android {0}; {1}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{2}.0.{3}.{4} Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android {0}; {1}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{2}.0.{3}.{4} Mobile Safari/537.36 EdgA/{5}.{6}.{7}.{8}'
    ]
    return desktop_agents if device_type == 'desktop' else mobile_agents

def generate_user_agent(device_type, template_index=None):
    templates = get_ua_templates(device_type)
    if template_index is not None:
        try:
            template = templates[int(template_index)]
        except (IndexError, ValueError):
            template = templates[0]
    else:
        template = templates[0]
    if device_type == 'mobile':
        versions = [random.randint(10, 14), random.randint(0, 5), 
                   random.randint(0, 9), random.randint(0, 9),
                   random.randint(100, 999), random.randint(80,120), random.randint(0,9), random.randint(0,9), random.randint(100,999)]
        return template.format(*versions)
    else:
        versions = [random.randint(80, 120), random.randint(0, 9),
                   random.randint(0, 9), random.randint(0, 9),
                   random.randint(100, 999)]
        return template.format(*versions)

@app.route('/ip-info', methods=['GET', 'POST'])
def ip_info():
    from flask import request, jsonify
    if request.method == 'POST':
        info = get_client_ip_info()
        return jsonify(info)
    else:
        info = get_client_ip_info()
        return render_template('ip_info.html', info=info)

# 获取客户端IP及相关信息
def get_client_ip_info():
    from flask import request
    info = {
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'accept': request.headers.get('Accept', ''),
        'accept_language': request.headers.get('Accept-Language', ''),
        'accept_encoding': request.headers.get('Accept-Encoding', ''),
        'referer': request.headers.get('Referer', ''),
        'host': request.headers.get('Host', ''),
        'connection': request.headers.get('Connection', ''),
        'x_forwarded_for': request.headers.get('X-Forwarded-For', ''),
        'x_real_ip': request.headers.get('X-Real-IP', ''),
        'method': request.method,
        'scheme': request.scheme,
        'protocol': request.environ.get('SERVER_PROTOCOL', ''),
        'port': request.environ.get('REMOTE_PORT', ''),
        'is_https': request.is_secure
    }
    return info


if __name__ == '__main__':
    app.run(debug=True, port=4303, host='0.0.0.0')



