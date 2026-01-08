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
import itertools
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

# ---- helper: HTTP ----
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

# ---- 保留原有参数填充逻辑 ----
def fill_parameters(parameters, url):
    """
    填充测试数据并替换 URL 中的占位符
    (保留原有逻辑)
    """
    kwargs = {}
    filled_params = {}
    path_params = {}
    for param in parameters:
        # 传进来的 param 可能是 dict {'name','in','type'}
        param_name = param.get('name')
        param_in = param.get('in')
        # 兼容 schema 的情况
        param_type = param.get('type') or (param.get('schema') or {}).get('type')

        # 根据类型填充默认值
        if param_type == 'string':
            value = 'a'
        elif param_type in ('integer', 'number'):
            value = 1
        elif param_type == 'boolean':
            value = True
        else:
            value = 'a' if param_type is None else ''

        if param_in == 'query':
            filled_params[param_name] = value
        elif param_in == 'path':
            path_params[param_name] = value
            filled_params[param_name] = value
        elif param_in in ('body', 'formData'):
            if 'body' not in filled_params:
                filled_params['body'] = {}
            filled_params['body'][param_name] = value

    # 替换 URL 中的占位符（用 path_params 的默认值）
    for key, value in path_params.items():
        url = url.replace(f'{{{key}}}', str(value))

    return filled_params, url

# ---- CSV 参数映射读取 ----
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

# ---- 构建要尝试的参数集合 ----
def build_param_sets(parameters, template_req_path, base_filled, csv_map, strategy, cartesian_cap=500):
    """
    返回一组要尝试的 (filled_params, url) 列表。
    - parameters: list of param dicts (with 'name' and 'in')
    - template_req_path: 原始包含 {var} 的 req_path
    - base_filled: fill_parameters 返回的基线 filled_params（包含 'body' 子 dict）
    - csv_map: dict param_name -> [values]
    - strategy: 'single' 或 'cartesian'
    """
    # 仅保留 CSV 中与 API 参数名匹配的参数
    param_name_to_in = {}
    for p in parameters:
        if not p.get('name'):
            continue
        param_name_to_in[p['name']] = p.get('in', 'query')

    csv_matched = {k: v for k, v in csv_map.items() if k in param_name_to_in and v}
    # 过滤掉空 value 列表（前面读 csv 时已过滤空值）

    # baseline：使用 base_filled（默认值）
    results = []

    # helper: deep copy of filled params structure
    def copy_filled(fp):
        new = {}
        for kk, vv in fp.items():
            if kk == 'body' and isinstance(vv, dict):
                new['body'] = dict(vv)
            else:
                new[kk] = vv
        return new

    def build_url_from_template(filled_for_url):
        # 从 template_req_path 替换所有 path 参数
        url = template_req_path
        # find path param names (pattern {name})
        for name in param_name_to_in:
            if param_name_to_in.get(name) == 'path':
                val = filled_for_url.get(name, '')
                url = url.replace('{' + name + '}', str(val))
        return url

    # add baseline
    baseline_filled = copy_filled(base_filled)
    baseline_url = build_url_from_template(baseline_filled)
    results.append((baseline_filled, baseline_url))

    if not csv_matched:
        return results

    # 单参数逐值尝试：对每个匹配参数，逐个使用 CSV 中的值替换（其他参数保持 base）
    if strategy == 'single':
        for pname, values in csv_matched.items():
            pin = param_name_to_in.get(pname, 'query')
            for val in values:
                fp = copy_filled(base_filled)
                # 根据 param 所在位置设置
                if pin in ('query', 'path'):
                    fp[pname] = val
                elif pin in ('body', 'formData'):
                    if 'body' not in fp:
                        fp['body'] = {}
                    fp['body'][pname] = val
                # build url
                url = build_url_from_template(fp)
                results.append((fp, url))
        return results

    # 全组合笛卡尔积
    if strategy == 'cartesian':
        keys = list(csv_matched.keys())
        lists = [csv_matched[k] for k in keys]
        total = 1
        for l in lists:
            total *= len(l)
        if total > cartesian_cap:
            logger.warning(f'Cartesian product size {total} exceeds cap {cartesian_cap}. Skipping cartesian generation.')
            return results
        for combo in itertools.product(*lists):
            fp = copy_filled(base_filled)
            for k, v in zip(keys, combo):
                pin = param_name_to_in.get(k, 'query')
                if pin in ('query', 'path'):
                    fp[k] = v
                elif pin in ('body', 'formData'):
                    if 'body' not in fp:
                        fp['body'] = {}
                    fp['body'][k] = v
            url = build_url_from_template(fp)
            results.append((fp, url))
        return results

    # unknown strategy fallback: return baseline
    logger.debug(f'未知 strategy={strategy}, 仅使用基线')
    return results

# ---- CSV 写入（保留） ----
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

# ---- 其余原有函数（资源解析 / swagger html 解析） ----
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

def go_resources(url):
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
            go_api_docs(target)  # 调用 api_docs 扫描全部接口

    except Exception as e:
        logger.error(f'[-] {url} error info {e}')

def go_swagger_html(url):
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
                go_api_docs(api_docs_url)
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
            go_resources(resource_url)
            return
    except Exception as e:
        logger.debug(f'[-] fetch {springfox_file_url} failed: {e}')

# ---- 主流程：解析 api-docs 并发送请求 ----
def go_api_docs(url, csv_map=None, strategy='single'):
    """
    开始 api-docs 解析并扫描
    csv_map: dict param -> [values]
    strategy: 'single' or 'cartesian'
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

        # 遍历每个接口项
        for item in swagger_result:
            summary = item['summary']
            req_path = item['req_path']
            method = item['method']
            consumes = item['consumes']
            parameters = item['parameters']

            # 基线填充（使用原有 fill_parameters）
            base_filled, base_filled_url = fill_parameters(parameters, req_path)
            # 生成要尝试的参数集合（根据 CSV 和策略）
            param_sets = build_param_sets(parameters, req_path, base_filled, csv_map or {}, strategy)

            headers = {}
            if 'application/json' in consumes:
                headers = {'Content-Type': 'application/json'}

            # 针对每个 param_set 发起请求
            for filled_params, attempt_url in param_sets:
                # 检查：如果 filled_params 中存在任意空字符串值，则跳过该组合
                has_empty = False
                # 检查 body
                if 'body' in filled_params:
                    for vv in filled_params['body'].values():
                        if isinstance(vv, str) and vv.strip() == '':
                            has_empty = True
                            break
                if has_empty:
                    logger.debug(f'[>] 跳过含空 body 值的组合 for {attempt_url}')
                    continue
                # 检查 query/path top-level params
                for k, vv in filled_params.items():
                    if k == 'body':
                        continue
                    if isinstance(vv, str) and vv.strip() == '':
                        has_empty = True
                        break
                if has_empty:
                    logger.debug(f'[>] 跳过含空参数值的组合 for {attempt_url}')
                    continue

                # 发送请求（根据 method）
                if method.lower() == 'get':
                    response = http_req(attempt_url, method='get', params=filled_params)
                    status = response.status_code
                    if status in black_list_status:
                        logger.warning(f'[-] BLACKLIST {method} {attempt_url} status {status}\nresponse: {response.text}')
                        # 黑名单只记录日志，不写 CSV
                        continue
                    logger.debug(f'[+] {method} {attempt_url} req status is {status}')
                    write_result = [url, attempt_url, summary, method, consumes, filled_params, status, response.text]
                    output_to_csv(write_result)

                elif method.lower() == 'post':
                    if 'body' in filled_params:
                        response = http_req(attempt_url, method='post', json=filled_params['body'], headers=headers)
                    else:
                        response = http_req(attempt_url, method='post', params=filled_params, headers=headers)

                    status = response.status_code
                    if status in black_list_status:
                        logger.warning(f'[-] BLACKLIST {method} {attempt_url} status {status}\nresponse: {response.text}')
                        continue
                    logger.debug(f'[+] {method} {attempt_url} req status is {status}')
                    write_result = [url, attempt_url, summary, method, consumes, filled_params, status, response.text]
                    output_to_csv(write_result)

                elif method.lower() == 'put':
                    if 'body' in filled_params:
                        response = http_req(attempt_url, method='put', json=filled_params['body'], headers=headers)
                    else:
                        response = http_req(attempt_url, method='put', params=filled_params, headers=headers)

                    status = response.status_code
                    if status in black_list_status:
                        logger.warning(f'[-] BLACKLIST {method} {attempt_url} status {status}\nresponse: {response.text}')
                        continue
                    logger.debug(f'[+] {method} {attempt_url} req status is {status}')
                    write_result = [url, attempt_url, summary, method, consumes, filled_params, status, response.text]
                    output_to_csv(write_result)

    except Exception as e:
        logger.error(f'[-] {url} error info {e}')

# ---- 运行入口 ----
def run(target, csv_map=None, strategy='single'):
    """
    执行程序
    """
    url_type = check_page(target)
    if url_type == 1:
        logger.success('working on {}'.format(target), 'type: source')
        go_resources(target)
    elif url_type == 2:
        logger.success('working on {}'.format(target), 'type: api-docs')
        go_api_docs(target, csv_map=csv_map, strategy=strategy)
    else:
        logger.success('working on {}'.format(target), 'type: html')
        go_swagger_html(target)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', dest='target_url', help='resource 地址 or api 文档地址 or swagger 首页地址')
    parser.add_argument('-f', '--file', dest='url_file', help='批量测试')
    parser.add_argument('-c', '--csv', dest='csv_file', help='可选：提供 CSV 文件 (key,value) 用于覆盖参数的取值', default=None)
    parser.add_argument('-s', '--strategy', dest='strategy', choices=['single', 'cartesian'], default='single',
                        help='参数值尝试策略：single=逐值单独尝 (默认)，cartesian=笛卡尔积穷尽所有组合')
    args = parser.parse_args()

    # 读取 CSV 映射（如果提供）
    csv_map = {}
    if args.csv_file:
        csv_map = read_csv_values(args.csv_file)
        logger.info(f'[+] loaded csv mapping for {len(csv_map)} keys from {args.csv_file}')

    logger.add('debug.log', format='{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}')
    if args.target_url:
        run(args.target_url, csv_map=csv_map, strategy=args.strategy)
    elif args.url_file:
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f.readlines()]
        for target_url in urls:
            print(target_url)
            run(target_url, csv_map=csv_map, strategy=args.strategy)