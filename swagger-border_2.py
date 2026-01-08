# -*- coding: utf-8 -*-

import json
import sys
import csv
import argparse
import requests
import re
import random
import urllib3
import os
from datetime import datetime
from urllib.parse import urlparse, urljoin
from loguru import logger

# 禁用安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger.remove()
handler_id = logger.add(sys.stderr, level='DEBUG')  # 设置输出级别

now_time = datetime.now().strftime("%Y%m%d_%H%M%S")

proxies = {
    'https': 'http://127.0.0.1:8080',
    'http': 'http://127.0.0.1:8080'
}

# 开启代理
SET_PROXY = True

#black_list_status = [401, 404, 502, 503]  # 状态码黑名单
black_list_status = []  # 状态码黑名单

header_agents = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.96.2 Chrome/128.0.6613.186 Electron/32.2.6 Safari/537.36'
]

CSV_FILE = f'{now_time}.csv'
CSV_HEADER = ['api-docs', 'address', 'description', 'Method', 'consumes', 'data', 'status_code', 'response']

def http_req(url, method='get', **kwargs):
    kwargs.setdefault('verify', False)
    kwargs.setdefault('timeout', (10.1, 30.1))
    kwargs.setdefault('allow_redirects', False)

    headers = kwargs.get('headers', {})
    headers.setdefault('User-Agent', random.choice(header_agents))
    # 不允许缓存，每次请求都获取服务器上最新的资源
    headers.setdefault('Cache-Control', 'max-age=0')
    kwargs['headers'] = headers
    if SET_PROXY:
        kwargs['proxies'] = proxies

    conn = getattr(requests, method)(url, **kwargs)
    return conn

def check_page(url):
    """
    检查当前页面
    """
    res = http_req(url, method='get')
    if '<html' in res.text:
        logger.debug('[+] 输入为 swagger 首页，开始解析 api 文档地址')
        return 3  # swagger-html
    elif '"parameters"' in res.text or '"paths"' in res.text:
        logger.debug('[+] 输入为 api 文档地址，开始构造请求发包')
        return 2  # api_docs
    elif '"location"' in res.text or '"url"' in res.text:
        logger.debug('[+] 输入为 resource 地址，开始解析 api 文档地址')
        return 1  # resource
    else:
        logger.debug('[?] 页面类型未明确 (默认按 swagger-html 处理)')
        return 3

def cast_csv_value(val, param_type):
    """
    尝试把 CSV 中的字符串值转换成合适类型，和 fill_parameters 的默认类型一致
    如果无法转换则返回字符串原值。
    空字符串或 None 返回 None（表示忽略）
    """
    if val is None:
        return None
    s = str(val).strip()
    if s == '':
        return None
    if param_type:
        t = param_type.lower()
        if t in ('integer', 'int', 'int32', 'int64'):
            try:
                return int(float(s))
            except Exception:
                return s
        if t in ('number', 'float', 'double'):
            try:
                return float(s)
            except Exception:
                return s
        if t == 'boolean':
            if s.lower() in ('true','1','yes','y'):
                return True
            if s.lower() in ('false','0','no','n'):
                return False
            return s
    # fallback string
    return s


def read_csv_values(csv_path):
    """
    读取用户提供的 CSV 映射，期望格式 key,value（如果存在 header 'key' 会被跳过）
    返回 dict: key -> [values...]，会过滤掉空字符串值，并尝试多种编码以避免解码错误。
    """
    import io

    CANDIDATE_ENCODINGS = ["utf-8", "utf-8-sig", "gb18030", "gbk", "gb2312", "big5", "cp1252", "latin1"]
    mapping = {}
    try:
        raw = open(csv_path, 'rb').read()
    except Exception as e:
        logger.error(f'[-] 读取 CSV 文件失败: {e}')
        return mapping

    decoded = None
    used_enc = None
    # 逐个尝试候选编码（严格解码以发现错误）
    for enc in CANDIDATE_ENCODINGS:
        try:
            decoded = raw.decode(enc)
            used_enc = enc
            break
        except Exception:
            continue

    # 额外尝试 latin1->utf-8 重解码修复
    if decoded is None:
        try:
            s_latin = raw.decode("latin1", errors="strict")
            decoded = s_latin.encode("latin1", errors="replace").decode("utf-8", errors="replace")
            used_enc = "latin1->utf-8"
        except Exception:
            # 最后兜底：尽量以 utf-8 忽略错误得到文本
            try:
                decoded = raw.decode("utf-8", errors="ignore")
                used_enc = "utf-8(ignore)"
            except Exception:
                decoded = None

    if decoded is None:
        logger.error(f'[-] 无法解码 CSV 文件: {csv_path}')
        return mapping

    logger.info(f'[+] CSV 文件解码使用: {used_enc}')

    try:
        s = io.StringIO(decoded)
        reader = csv.reader(s)
        rows = list(reader)
    except Exception as e:
        logger.error(f'[-] 解析 CSV 内容失败: {e}')
        return mapping

    if not rows:
        return mapping

    # 如果第一行看起来是 header (包含 key 或 value)，从第二行开始
    start = 0
    header = [c.strip().lower() for c in rows[0]]
    if 'key' in header or 'value' in header:
        start = 1

    for r in rows[start:]:
        if not r:
            continue
        # 有些 CSV 行可能只有一个字段或多余字段，按最常见的 key,value 解析
        if len(r) == 1:
            k = r[0].strip()
            v = ''
        else:
            k = str(r[0]).strip()
            v = str(r[1]).strip()
        if k == '':
            continue
        if v == '':
            # 忽略空值（用户要求：参数值为空时不要输出 / 不使用）
            continue
        mapping.setdefault(k, []).append(v)

    return mapping

def fill_parameters(parameters, url, csv_params=None):
    """
    填充测试数据并替换 URL 中的占位符
    新增功能：如果 csv_params 中存在与参数名相同的值且非空，则优先使用 csv 中的值（cast 后使用）。
    csv_params: dict key -> list of values (使用第一个有效值)
    """
    filled_params = {}
    path_params = {}
    csv_params = csv_params or {}

    for param in parameters:
        param_name = param.get('name')
        param_in = param.get('in')
        param_type = param.get('type') or (param.get('schema') or {}).get('type')

        # 如果 csv 提供了该参数且有非空值则优先使用
        csv_val = None
        if param_name and param_name in csv_params and csv_params[param_name]:
            # 使用第一个非空 CSV 值
            candidate = csv_params[param_name][0]
            # 解析可能是 JSON 的 body 值：如果看起来像 JSON 则尝试解析
            if isinstance(candidate, str) and (candidate.strip().startswith('{') or candidate.strip().startswith('[')):
                try:
                    parsed = json.loads(candidate)
                    csv_val = parsed
                except Exception:
                    csv_val = candidate
            else:
                csv_val = candidate
            # cast 基本类型
            csv_val = cast_csv_value(csv_val, param_type)

        # 根据类型填充默认值（当没有 csv_val 提供时）
        if csv_val is None:
            if param_type == 'string':
                value = 'a'
            elif param_type in ('integer', 'number'):
                value = 1
            elif param_type == 'boolean':
                value = True
            else:
                value = 'a' if param_type is None else ''
        else:
            value = csv_val

        if param_in == 'query':
            filled_params[param_name] = value
            logger.debug(f"[+] param query '{param_name}' set to '{value}' (from CSV override: {param_name in csv_params})")
        elif param_in == 'path':
            path_params[param_name] = value
            filled_params[param_name] = value
            logger.debug(f"[+] param path '{param_name}' set to '{value}' (from CSV override: {param_name in csv_params})")
        elif param_in in ('body', 'formData'):
            if 'body' not in filled_params:
                filled_params['body'] = {}
            filled_params['body'][param_name] = value
            logger.debug(f"[+] param body/formData '{param_name}' set to '{value}' (from CSV override: {param_name in csv_params})")

    # 替换 URL 中的占位符
    for key, value in path_params.items():
        try:
            url = url.replace(f'{{{key}}}', str(value))
        except Exception:
            url = url

    return filled_params, url

def get_api_docs_path(resource_url):
    """
    输入 resource 解析 api 文档 url
    """
    domain = urlparse(resource_url)
    base = domain.scheme + '://' + domain.netloc
    try:
        res = http_req(resource_url, method='get')
        resources = json.loads(res.text)
    except Exception as e:
        logger.error(f'[-] {resource_url} error info {e}')
        return []

    paths = []
    if isinstance(resources, dict) and 'apis' in resources:
        for api_docs in resources.get('apis', []):
            p = api_docs.get('path')
            if p:
                if p.startswith('http'):
                    paths.append(p)
                else:
                    paths.append(base + p)
        return paths
    else:
        # 资源数组，通常包含 location 字段
        for i in resources:
            loc = i.get('location') or i.get('url')
            if loc:
                if loc.startswith('http'):
                    paths.append(loc)
                else:
                    paths.append(base + loc)
        return paths

def output_to_csv(data):
    """
    写 CSV，确保行不被 response.text 中的换行打断。
    把真实换行替换为转义序列 '\\n'，确保 CSV 每条是一行。
    如果文件不存在或为空，则先写入标题行。
    """
    safe_row = []
    for v in data:
        if isinstance(v, str):
            # 将真实换行替换为可识别的 \n，避免 CSV 行断裂
            s = v.replace('\r\n', '\\n').replace('\n', '\\n').replace('\r', '\\n')
            safe_row.append(s)
        else:
            try:
                safe_row.append(json.dumps(v, ensure_ascii=False))
            except Exception:
                safe_row.append(str(v))

    # 确保目录存在（当前脚本写当前目录，通常不必要）
    # 写入 CSV（追加模式），并在文件为空时写 header
    write_header = False
    if not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0:
        write_header = True

    with open(CSV_FILE, 'a', newline='', encoding='utf-8') as _f:
        writer = csv.writer(_f, quoting=csv.QUOTE_MINIMAL)
        if write_header:
            writer.writerow(CSV_HEADER)
        writer.writerow(safe_row)

def go_resources(url, csv_params=None):
    """
    解析 swagger-resources 获取 api-docs
    """
    try:
        _domain = urlparse(url)
        domain = _domain.scheme + '://' + _domain.netloc
        domain_path = _domain.path
        stripped_path = domain_path.strip('/')
        res = http_req(url)
        data = json.loads(res.text)
        for _i in data:
            location = _i.get('location') or _i.get('url')
            if not location:
                continue
            # 如果 location 是绝对地址则直接使用，否则按原路径拼接或以 domain 拼接
            if location.startswith('http'):
                target = location
            else:
                if len(stripped_path) > 0:
                    target = url.rsplit('/', 1)[0] + location
                else:
                    target = domain + location
            go_api_docs(target, csv_params=csv_params)  # 传递 csv_params

    except Exception as e:
        logger.error(f'[-] {url} error info {e}')

def go_swagger_html(url, csv_params=None):
    """
    解析 swagger-ui.html 获取 api 接口路径
    """
    response = http_req(url)
    response.raise_for_status()
    html_content = response.text
    # 在 swagger-initializer.js 中获取 swagger.json 接口
    initializer_pattern = r'<script\s+src=["\']([^"\']*swagger-initializer\.js[^"\']*)["\']'
    initializer_match = re.search(initializer_pattern, html_content)
    base_url = None
    if initializer_match:
        js_file_path = initializer_match.group(1)
        if js_file_path.startswith('http'):
            js_file_url = js_file_path
        else:
            # 构造相对到绝对路径
            js_file_url = urljoin(url, js_file_path)
        try:
            js_response = http_req(js_file_url)
            js_response.raise_for_status()
            js_content = js_response.text

            # 正则获取 defaultDefinitionUrl 的值 swagger.json 接口路径
            js_pattern = r'const\s+defaultDefinitionUrl\s*=\s*["\']([^"\']+)["\'];'
            js_match = re.search(js_pattern, js_content)
            if js_match:
                api_docs_path = js_match.group(1)
                # api_docs_path 可能是相对路径，需要拼接
                api_docs_url = api_docs_path if api_docs_path.startswith('http') else urljoin(js_file_url, api_docs_path)
                go_api_docs(api_docs_url, csv_params=csv_params)
                return
        except Exception as e:
            logger.debug(f'[-] fetch {js_file_url} failed: {e}')

    # 未找到 swagger-initializer.js 文件或 defaultDefinitionUrl 定义, 则尝试查找 springfox.js 文件
    springfox_pattern = r'<script\s+src=["\']([^"\']*springfox\.js[^"\']*)["\']'
    springfox_match = re.search(springfox_pattern, html_content)
    if not springfox_match:
        logger.debug('[-] 未找到 swagger-initializer.js 和 springfox.js 文件路径')
        return

    # 获取 springfox.js 文件的相对或绝对路径
    springfox_file_path = springfox_match.group(1)
    if springfox_file_path.startswith('http'):
        springfox_file_url = springfox_file_path
    else:
        springfox_file_url = urljoin(url, springfox_file_path)

    # 发送请求获取 springfox.js 文件内容
    try:
        springfox_response = http_req(springfox_file_url)
        springfox_response.raise_for_status()
        springfox_content = springfox_response.text
        if "/swagger-resources" in springfox_content:
            base = url.rsplit('/', 1)[0]
            resource_url = urljoin(base + '/', "/swagger-resources")
            go_resources(resource_url, csv_params=csv_params)
            return
    except Exception as e:
        logger.debug(f'[-] fetch {springfox_file_url} failed: {e}')

def go_api_docs(url, csv_params=None):
    """
    开始 api-docs 解析并扫描
    """
    try:
        _parsed = urlparse(url)
        domain = _parsed.scheme + '://' + _parsed.netloc

        res = http_req(url)
        if res.status_code != 200:
            logger.error(f'[-] {url} req status is {res.status_code}')
            return
        try:
            data = json.loads(res.text)
        except json.JSONDecodeError:
            # 遇到 html 标签内存在双引号 json.loads 无法格式化, 需要特殊处理
            data = res.text.replace("'", '"')
            result = re.sub(r'<[^>]*>', lambda match: match.group(0).replace('"', "'"), data)
            data = json.loads(result, strict=False)

        # 计算 base_url（兼容 swagger 2 basePath / openapi v3 servers）
        base_url = domain
        if isinstance(data, dict) and 'basePath' in data and data.get('basePath'):
            bp = data.get('basePath')
            if bp.startswith('http'):
                base_url = bp
            else:
                base_url = domain.rstrip('/') + '/' + bp.lstrip('/')
        elif isinstance(data, dict) and 'servers' in data and isinstance(data['servers'], list) and len(data['servers']) > 0:
            server_url = data['servers'][0].get('url', '')
            if server_url.startswith('http'):
                base_url = server_url
            else:
                base_url = domain.rstrip('/') + '/' + server_url.lstrip('/')
        else:
            base_url = domain

        paths = (data.get('paths', {}) if isinstance(data, dict) else {})
        definitions = data.get('definitions', {}) if isinstance(data, dict) else {}
        swagger_result = []
        for path, methods in paths.items():
#            path = path.replace("/dssn/", "/dssn/stage-api/", 1)
            for method, details in methods.items():  # get / post / put / update / delete / head...
                if method.upper() not in ['GET', 'POST', 'PUT']:  # http 请求方式白名单
                    continue

                # req_path：如果 base_url 是完整 url（包含域和可能的 path），拼接 paths 时用 urljoin 更稳健
                req_path = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
                summary = details.get('summary', path)  # 概要信息
                consumes = details.get('consumes', [])  # 数据请求类型 application/json
                params = details.get('parameters', [])
                logger.debug(f'test on {summary} => {method} => {req_path}')
                param_info = []
                for param in params:
                    param_name = param.get('name')
                    param_in = param.get('in')
                    schema = param.get('schema')
                    # 判断是否存在自定义的模型或对象
                    if schema and isinstance(schema, dict) and '$ref' in schema:
                        ref = schema['$ref'].split('/')[-1]
                        if ref in definitions:  # 如果在 definitions 中声明了参数属性，则去 definitions 定义中获取参数及属性信息
                            # 递归处理定义中的属性
                            for prop_name, prop_details in definitions[ref].get('properties', {}).items():
                                param_info.append({
                                    'name': prop_name,
                                    'in': param_in,
                                    'type': prop_details.get('type')
                                })
                    else:
                        param_type = param.get('type')
                        param_info.append({
                            'name': param_name,
                            'in': param_in,
                            'type': param_type
                        })

                # 解析 swagger 获取到所有需要的数据
                swagger_result.append({
                    'summary': summary,
                    'req_path': req_path,
                    'method': method,
                    'consumes': consumes,
                    'parameters': param_info
                })


        for item in swagger_result:
            summary = item['summary']
            req_path = item['req_path']
            method = item['method']
            consumes = item['consumes']
            parameters = item['parameters']
            # 生成发送的 Body 数据
            filled_params, new_url = fill_parameters(parameters, req_path, csv_params=csv_params)
            headers = {}

            if 'application/json' in consumes:
                headers = {'Content-Type': 'application/json'}

            # 统一把成功判定改为任何非黑名单都写到 CSV；黑名单状态则写日志
            if method.lower() == 'get':
                response = http_req(new_url, method='get', params=filled_params)
                status = response.status_code
                if status in black_list_status:
                    logger.warning(f'[-] BLACKLIST {method} {new_url} status {status}\nresponse: {response.text}')
                    # 不写入 CSV（按你的要求），仅打印到日志
                    continue
                # 其余所有状态码都写入 CSV
                logger.debug(f'[+] {method} {new_url} req status is {status}')
                write_result = [url, new_url, summary, method, consumes, filled_params, status, response.text]
                output_to_csv(write_result)

            elif method.lower() == 'post':
                if 'body' in filled_params:
                    # 如果 csv 给出的 body 字段是 dict/object，我们已经保留了该结构
                    response = http_req(new_url, method='post', json=filled_params['body'], headers=headers)
                else:
                    response = http_req(new_url, method='post', params=filled_params, headers=headers)

                status = response.status_code
                if status in black_list_status:
                    logger.warning(f'[-] BLACKLIST {method} {new_url} status {status}\nresponse: {response.text}')
                    continue
                logger.debug(f'[+] {method} {new_url} req status is {status}')
                write_result = [url, new_url, summary, method, consumes, filled_params, status, response.text]
                output_to_csv(write_result)

            elif method.lower() == 'put':
                if 'body' in filled_params:
                    response = http_req(new_url, method='put', json=filled_params['body'], headers=headers)
                else:
                    response = http_req(new_url, method='put', params=filled_params, headers=headers)

                status = response.status_code
                if status in black_list_status:
                    logger.warning(f'[-] BLACKLIST {method} {new_url} status {status}\nresponse: {response.text}')
                    continue
                logger.debug(f'[+] {method} {new_url} req status is {status}')
                write_result = [url, new_url, summary, method, consumes, filled_params, status, response.text]
                output_to_csv(write_result)

    except Exception as e:
        logger.error(f'[-] {url} error info {e}')

def run(target, csv_params=None):
    """
    执行程序
    """
    url_type = check_page(target)
    if url_type == 1:
        logger.success('working on {}'.format(target), 'type: source')
        go_resources(target, csv_params=csv_params)
    elif url_type == 2:
        logger.success('working on {}'.format(target), 'type: api-docs')
        go_api_docs(target, csv_params=csv_params)
    else:
        logger.success('working on {}'.format(target), 'type: html')
        go_swagger_html(target, csv_params=csv_params)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', dest='target_url', help='resource 地址 or api 文档地址 or swagger 首页地址')
    parser.add_argument('-f', '--file', dest='url_file', help='批量测试')
    parser.add_argument('-c', '--csv-params', dest='csv_params', help='CSV 参数文件路径（key,value），优先使用 CSV 中的参数值覆盖 api-docs 参数值（空值会被忽略）')
    args = parser.parse_args()

    logger.add('debug.log', format='{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}')

    csv_params_map = {}
    if args.csv_params:
        csv_params_map = read_csv_values(args.csv_params)
        logger.info(f'[+] loaded csv params: {len(csv_params_map)} keys from {args.csv_params}')

    if args.target_url:
        run(args.target_url, csv_params=csv_params_map)
    elif args.url_file:
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f.readlines()]
        for target_url in urls:
            print(target_url)
            run(target_url, csv_params=csv_params_map)