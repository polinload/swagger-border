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
import copy
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
SET_PROXY = False

#black_list_status = [401, 404, 502, 503]  # 状态码黑名单
black_list_status = []  # 状态码黑名单

# ========== 新增配置（在代码中设置，不通过 CLI） ==========
# 白名单：只对这些参数启用多值组合（如果启用 -m 模式）
# 示例：VARY_PARAM_WHITELIST = ['id', 'status', 'apiCode']
# 将其置为空列表则不会对任意参数做多值尝试（尽管 -m 被开启）
VARY_PARAM_WHITELIST = ['id', 'fieldId', 'accessAddress']

# 每个 API 的最大请求数阈值（当组合数 > 此阈值时会被截断为阈值数量）
# 设为整数，例如 500。设为 None 或 0 表示不限制。
MAX_REQUESTS_PER_API = 500
# ============================================================

# ========== 新增：接口路径黑名单配置（在代码中设置，不通过 CLI） ==========
# 这里填写不希望被程序测试的接口路径（仅放路径部分即可），支持三种写法：
# 1) 精确路径，如 '/api/switch/roles'（会与 URL 的 path 部分做严格匹配，斜杠结尾会被忽略）
# 2) 前缀通配符，如 '/api/admin/*' （末尾使用 '*' 表示以该前缀开头的所有路径都被屏蔽）
# 3) 正则表达式，以 're:' 开头，例如 're:^/internal/.*' （会对整个请求 URL 使用 re.search）
# 示例：black_list_paths = ['/api/switch/roles', '/api/admin/*', 're:^/internal/.*']
black_list_paths = ['/api/switch/roles']
# ============================================================

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
#    headers.setdefault('Authorization', 'eyJhbGciOiJIUzUxMiJ9.eyJsb2dpbl91c2VyX2tleSI6IjIzZTAzMmY0LWNkMDgtNDJhZC04YTk0LWMzZGViMzk2ZDIyNCJ9.ZEoeHvdT4FDwyONbCH0MBE6_MGkIOABzjVIv3e-IUDsj9q14rthnFrgqD_hJ3ehP2-N_1YEbOsA3__-oyiCcrQ')
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
    # 如果已经是非字符串（例如 json.loads 解析后为 dict/list），直接返回
    if not isinstance(val, str):
        return val

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
    原有行为：如果 csv_params 中存在与参数名相同的值且非空，则优先使用 CSV 中的第一个值（cast 后使用）。
    返回: filled_params, url (single-case)

    已增强对 body schema 的支持：
    - 如果参数列表中存在 name=='body' 并带有 'schema' 字段，则构建符合 schema 的嵌套对象作为 body 示例。
    - 会尝试应用 CSV 中对嵌套字段的覆盖（通过在 body 中递归查找字段名并赋值）。
    """
    filled_params = {}
    path_params = {}
    csv_params = csv_params or {}

    def set_nested_property(obj, key, value):
        """
        在嵌套 dict/list 中查找第一个匹配 key 的位置并设置值（用于 CSV 覆盖）。
        返回 True 表示已设置，否则 False。
        """
        if isinstance(obj, dict):
            if key in obj:
                obj[key] = value
                return True
            for k, v in obj.items():
                if isinstance(v, dict):
                    if set_nested_property(v, key, value):
                        return True
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            if set_nested_property(item, key, value):
                                return True
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    if set_nested_property(item, key, value):
                        return True
        return False

    for param in parameters:
        param_name = param.get('name')
        param_in = param.get('in')
        # param_type 可能不存在（复杂对象）
        param_type = param.get('type') or (param.get('schema') or {}).get('type')

        # 特殊处理：如果这是一个整体 body schema（param_name == 'body' 且包含 schema），构建嵌套示例
        if param_in in ('body', 'formData') and param_name == 'body' and isinstance(param.get('schema'), dict):
            # 使用 schema 构建示例对象（递归）
            example = build_example_from_schema(param['schema'], globals_definitions)
            # 允许 CSV 覆盖 body 内部字段（根据键名在 body 内递归查找并替换第一个匹配）
            for csv_key, csv_vals in (csv_params or {}).items():
                if not csv_vals:
                    continue
                csv_candidate = csv_vals[0]
                # 尝试解析 JSON 字符串值
                final_val = csv_candidate
                if isinstance(csv_candidate, str) and csv_candidate.strip().startswith(('{', '[')):
                    try:
                        final_val = json.loads(csv_candidate)
                    except Exception:
                        final_val = csv_candidate
                final_val = cast_csv_value(final_val, None)
                set_nested_property(example, csv_key, final_val)
            filled_params['body'] = example
            logger.debug(f"[+] param body (schema) set to example (from schema), keys_overridden={list(csv_params.keys())}")
            continue

        # 如果 csv 提供了该参数且有非空值则优先使用第一个值（针对非复杂 body 情况）
        csv_val = None
        if param_name and param_name in csv_params and csv_params[param_name]:
            candidate = csv_params[param_name][0]
            if isinstance(candidate, str) and (candidate.strip().startswith('{') or candidate.strip().startswith('[')):
                try:
                    parsed = json.loads(candidate)
                    csv_val = parsed
                except Exception:
                    csv_val = candidate
            else:
                csv_val = candidate
            csv_val = cast_csv_value(csv_val, param_type)

        # 根据类型填充默认值（当没有 csv_val 提供时）
        if csv_val is None:
            if param_type == 'string':
                value = 'admin'
            elif param_type in ('integer', 'number'):
                value = 1
            elif param_type == 'boolean':
                value = True
            else:
                value = 'admin' if param_type is None else ''
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
            # 非整体 schema 的 body 属性（例如早期把 schema 展开为多个参数的情形）
            if 'body' not in filled_params or not isinstance(filled_params['body'], dict):
                filled_params['body'] = {}
            filled_params['body'][param_name] = value
            logger.debug(f"[+] param body/formData '{param_name}' set to '{value}' (from CSV override: {param_name in csv_params})")
        else:
            filled_params[param_name] = value

    # 替换 URL 中的占位符
    for key, value in path_params.items():
        try:
            url = url.replace(f'{{{key}}}', str(value))
        except Exception:
            url = url

    return filled_params, url

def generate_param_combinations(parameters, url, csv_params=None):
    """
    生成参数组合（笛卡尔积），用于当用户启用 --multi 时：
    - 仅对白名单参数 (VARY_PARAM_WHITELIST) 使用 CSV 中的多值（否则使用第一个值或默认）
    - 如果生成的组合数超过 MAX_REQUESTS_PER_API，会截断为阈值数量（随机抽样以保留多样性）
    返回 list of (filled_params, new_url)

    已增强：当遇到整体 body schema 时，使用构建的示例作为唯一候选（避免把 schema 展开成大量扁平字段）
    """
    csv_params = csv_params or {}
    candidates_list = []
    param_meta = []  # keep metadata for each param (name, in, type, param_dict)

    for param in parameters:
        param_name = param.get('name')
        param_in = param.get('in')
        param_type = param.get('type') or (param.get('schema') or {}).get('type')
        param_meta.append((param_name, param_in, param_type, param))

        vals = []
        # 如果这是整体 body schema 参数，直接使用构建的示例作为唯一候选
        if param_name == 'body' and isinstance(param.get('schema'), dict):
            example = build_example_from_schema(param['schema'], globals_definitions)
            vals.append(example)
            candidates_list.append(vals)
            continue

        # 如果参数在白名单内，则用该参数在 CSV 中的所有值（如果存在），否则仅使用第一个值（若 CSV 提供）
        if param_name and param_name in csv_params and csv_params[param_name]:
            raw_vals = csv_params[param_name]
            if param_name in VARY_PARAM_WHITELIST:
                # 白名单：使用所有候选值（但后续会以 MAX_REQUESTS_PER_API 做全局截断）
                for candidate_raw in raw_vals:
                    if isinstance(candidate_raw, str) and candidate_raw.strip().startswith(('{', '[')):
                        try:
                            parsed = json.loads(candidate_raw)
                            vals.append(parsed)
                            continue
                        except Exception:
                            pass
                    vals.append(cast_csv_value(candidate_raw, param_type))
            else:
                # 非白名单：仍然使用 CSV 提供的第一个值（保持原行为）
                candidate = raw_vals[0]
                if isinstance(candidate, str) and candidate.strip().startswith(('{', '[')):
                    try:
                        parsed = json.loads(candidate)
                        vals.append(parsed)
                    except Exception:
                        vals.append(cast_csv_value(candidate, param_type))
                else:
                    vals.append(cast_csv_value(candidate, param_type))
        else:
            # 没有 CSV 提供，使用默认单个候选值
            if param_type == 'string':
                vals.append('admin')
            elif param_type in ('integer', 'number'):
                vals.append(1)
            elif param_type == 'boolean':
                vals.append(True)
            else:
                if param_in in ('body', 'formData') and (param_name == 'body' or param_name is None):
                    vals.append({})
                else:
                    vals.append('admin' if param_type is None else '')

        if not vals:
            vals = [None]
        candidates_list.append(vals)

    # 估算组合数量
    total_combinations = 1
    for c in candidates_list:
        total_combinations *= max(1, len(c))
    logger.info(f'[+] 预计参数组合数: {total_combinations} for url {url}')

    # 生成所有组合（注意：若 total_combinations 很大这会占内存）
    results = []
    for combo in itertools.product(*candidates_list):
        filled = {}
        path_params = {}
        for (param_name, param_in, param_type, param_obj), val in zip(param_meta, combo):
            if param_name is None:
                continue
            if param_in == 'query':
                filled[param_name] = val
            elif param_in == 'path':
                path_params[param_name] = val
                filled[param_name] = val
            elif param_in in ('body', 'formData'):
                if param_name == 'body':
                    filled['body'] = val
                else:
                    if 'body' not in filled or not isinstance(filled['body'], dict):
                        filled['body'] = {}
                    filled['body'][param_name] = val
            else:
                filled[param_name] = val

        new_url = url
        for k, v in path_params.items():
            try:
                new_url = new_url.replace(f'{{{k}}}', str(v))
            except Exception:
                pass

        results.append((filled, new_url))

    # 如果设置了 MAX_REQUESTS_PER_API 且组合数超过阈值，则随机抽样截断为阈值数量
    if isinstance(MAX_REQUESTS_PER_API, int) and MAX_REQUESTS_PER_API > 0 and len(results) > MAX_REQUESTS_PER_API:
        logger.warning(f'[-] 组合数 {len(results)} 超过阈值 {MAX_REQUESTS_PER_API}，将随机抽样截断为 {MAX_REQUESTS_PER_API} 个请求以限制负载')
        results = random.sample(results, MAX_REQUESTS_PER_API)

    return results


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
    如果文件不存在或为空，则先写��标题行。
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

def go_resources(url, csv_params=None, multi=False):
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
            # 如果 location 是绝对地址则直接使用，否则按原路��拼接或以 domain 拼接
            if location.startswith('http'):
                target = location
            else:
                if len(stripped_path) > 0:
                    target = url.rsplit('/', 1)[0] + location
                else:
                    target = domain + location
            go_api_docs(target, csv_params=csv_params, multi=multi)  # 传递 csv_params 和 multi

    except Exception as e:
        logger.error(f'[-] {url} error info {e}')

def go_swagger_html(url, csv_params=None, multi=False):
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
                go_api_docs(api_docs_url, csv_params=csv_params, multi=multi)
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
            go_resources(resource_url, csv_params=csv_params, multi=multi)
            return
    except Exception as e:
        logger.debug(f'[-] fetch {springfox_file_url} failed: {e}')

# ---------- 新增：从 schema 构建示例对象（支持 $ref、properties、items、allOf/oneOf/anyOf） ----------
def build_example_from_schema(schema, definitions, seen=None):
    """
    递归构建 schema 的示例值（用于作为 requestBody 的 body 示例）。
    - 对 $ref 自动展开（并防止循环引用）
    - 对 object 类型生成 dict，对 array 生成包含单个示例元素的 list
    - 对 primitive 类型返回默认示例值
    遇到循环引用（同一个 $ref 重复出现）时返回 None（匹配 swagger-ui 常见表现）
    """
    if schema is None:
        return None
    if seen is None:
        seen = set()

    # 如果 schema 是布尔/非法类型，直接返回 None
    if not isinstance(schema, dict):
        return None

    # 处理 $ref
    if '$ref' in schema:
        ref_name = schema['$ref'].split('/')[-1]
        if ref_name in seen:
            # 避免无限递归，返回 None 代表递归占位（和 swagger-ui 的 children: [null] 类似）
            return None
        seen.add(ref_name)
        model = definitions.get(ref_name)
        if model and isinstance(model, dict):
            # model 可能包含 allOf/oneOf/anyOf 或 properties
            return build_example_from_schema(model, definitions, seen)

        # 找不到 ref 定义，返回 None
        return None

    # 组合类型
    for comb in ('allOf', 'oneOf', 'anyOf'):
        if comb in schema and isinstance(schema[comb], list):
            # 对于 allOf：合并 dict 示例；oneOf/anyOf：取第一个示例
            if comb == 'allOf':
                merged = {}
                for item in schema[comb]:
                    ex = build_example_from_schema(item, definitions, seen.copy())
                    if isinstance(ex, dict):
                        merged.update(ex)
                return merged
            else:
                # oneOf/anyOf 取第一个有效示例
                for item in schema[comb]:
                    ex = build_example_from_schema(item, definitions, seen.copy())
                    if ex is not None:
                        return ex
                return None

    t = schema.get('type')
    if t == 'object' or ('properties' in schema and isinstance(schema.get('properties'), dict)):
        result = {}
        props = schema.get('properties', {})
        for prop_name, prop_schema in props.items():
            # 如果子属性有 example 字段优先使用
            if isinstance(prop_schema, dict) and 'example' in prop_schema:
                result[prop_name] = copy.deepcopy(prop_schema['example'])
                continue
            child = build_example_from_schema(prop_schema, definitions, seen.copy())
            # 对于可能返回 None（循环引用等），保留 None，匹配 swagger-ui 的展示
            result[prop_name] = child
        return result

    if t == 'array':
        items = schema.get('items')
        item_example = build_example_from_schema(items, definitions, seen.copy())
        # 有时 swagger-ui 展示 children: [null]，因此当 item_example 为 None 时保留 [None]
        return [item_example]

    # primitive types
    fmt = schema.get('format', '')
    if t == 'string':
        if fmt == 'date-time' or fmt == 'date':
            # 返回 ISO8601 示例
            return datetime.utcnow().isoformat() + 'Z'
        return 'string'
    if t in ('integer', 'int32', 'int64'):
        return 0
    if t in ('number', 'float', 'double'):
        return 0.0
    if t == 'boolean':
        return True

    # fallback: 如果 schema 指定了 enum，返回第一个枚举值
    if 'enum' in schema and isinstance(schema['enum'], list) and schema['enum']:
        return schema['enum'][0]

    # 无法判定则返回 None
    return None
# ---------- 结束新增 ----------

def go_api_docs(url, csv_params=None, multi=False):
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
        # 合并 definitions 与 components.schemas（优先 components）
        definitions = {}

        if isinstance(data, dict):
            # swagger 2.0 definitions
            if 'definitions' in data and isinstance(data['definitions'], dict):
                definitions.update(data['definitions'])
            # openapi 3.0 components.schemas
            components = (data.get('components') or {}).get('schemas') if isinstance(data.get('components'), dict) else None
            if components and isinstance(components, dict):
                # components schema 优先覆盖 definitions 中的同名项
                definitions.update(components)

        # 将 definitions 暴露给 fill_parameters / build_example 使用（全局变量引用）
        global globals_definitions
        globals_definitions = definitions

        base_url = domain

        paths = (data.get('paths', {}) if isinstance(data, dict) else {})

        swagger_result = []

        def resolve_schema_properties(schema):
            """
            给定一个 schema（可能是 $ref 或者 有 properties 字段），返回一个 list of {name, type, in}
            旧的扁平化展开保留兼容性，但我们不再依赖此函数来构建复杂 body 的示例对象。
            """
            props = []
            if not schema:
                return props
            if isinstance(schema, dict) and '$ref' in schema:
                ref_name = schema['$ref'].split('/')[-1]
                model = definitions.get(ref_name)
                if model and isinstance(model, dict):
                    for prop_name, prop_details in model.get('properties', {}).items():
                        props.append({
                            'name': prop_name,
                            'type': prop_details.get('type'),
                            'in': 'body'
                        })
            elif isinstance(schema, dict) and 'properties' in schema:
                for prop_name, prop_details in schema.get('properties', {}).items():
                    props.append({
                        'name': prop_name,
                        'type': prop_details.get('type'),
                        'in': 'body'
                    })
            return props

        # ---------- 新增：黑名单匹配函数（中文注释） ----------
        def is_path_blacklisted(full_url):
            """
            判断给定的完整 URL 是否命中黑名单（black_list_paths）。
            支持三种规则：
              - 're:...' 正则匹配（对整个 URL 使用 re.search）
              - 以 '*' 结尾的前缀匹配（基于 path 部分）
              - 精确路径匹配（基于 path，忽略是否以 / 结尾）
            返回 True 表示该接口应被跳过（不进行测试）。
            """
            p = urlparse(full_url).path
            for pattern in (black_list_paths or []):
                if not pattern:
                    continue
                # 正则匹配
                if pattern.startswith('re:'):
                    try:
                        if re.search(pattern[3:], full_url):
                            return True
                    except re.error:
                        # 正则错误则跳过该模式
                        continue
                # 前缀通配符 '/api/admin/*'
                elif pattern.endswith('*'):
                    prefix = pattern[:-1]
                    if p.startswith(prefix):
                        return True
                else:
                    # 精确路径匹配，忽略尾部斜杠差异；同时兼容传入 pattern 为完整 URL 的情况
                    try:
                        pattern_path = urlparse(pattern).path if pattern.startswith('http') else pattern
                    except Exception:
                        pattern_path = pattern
                    if p == pattern_path or p.rstrip('/') == pattern_path.rstrip('/'):
                        return True
                    # 兼容：有时用户填写的是 '/roles'，而 req_path 可能是 '/api/switch/roles'，支持后缀匹配
                    if p.endswith(pattern_path):
                        return True
            return False
        # ---------- 结束新增 ----------

        for path, methods in paths.items():
#            path = path.replace("/dssn/", "/dssn/stage-api/", 1)
            for method, details in methods.items():  # get / post / put / update / delete / head...
                if method.upper() not in ['GET', 'POST', 'PUT']:  # http 请求方式白名单
                    continue

                # req_path：如果 base_url 是完整 url（包含域和可能的 path），拼接 paths 时用 urljoin 更稳健
                req_path = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
                summary = details.get('summary', path)  # 概要信息

                # --------- 新增：在构造请求之前检查路径黑名单（中文注释） ----------
                # 如果匹配到黑名单，则跳过该接口，不进行参数填充和发包测试
                if is_path_blacklisted(req_path):
                    logger.warning(f'[-] 跳过黑名单接口 {req_path}')
                    continue
                # --------------------------------------------------------------------

                # collects consumes/content types
                consumes = details.get('consumes') or []

                # OpenAPI3 uses requestBody.content
                if not consumes and isinstance(details.get('requestBody'), dict):
                    content = details['requestBody'].get('content', {})
                    if isinstance(content, dict):
                        consumes = list(content.keys())

                params = details.get('parameters', []) or []
                # 如果是 OpenAPI3，可能存在 requestBody
                if isinstance(details.get('requestBody'), dict):
                    rb = details['requestBody']
                    content = rb.get('content', {})
                    # 遍历每个 media type，取第一个可用的 schema 合并为 body param
                    if isinstance(content, dict):
                        for media_type, media_obj in content.items():
                            schema = media_obj.get('schema')
                            # 不再把 schema 展开为扁平字段，而是作为整体 body schema 记录，
                            # 以便 later 构建出符合 schema 的嵌套 JSON 示例（包括 nested $ref）
                            params.append({
                                'name': 'body',
                                'in': 'body',
                                'type': None,
                                'schema': schema
                            })
                            # 只需要第一个 media type 来构造参数（否则会重复）
                            break

                logger.debug(f'test on {summary} => {method} => {req_path}')
                param_info = []

                for param in params:
                    # param 可能直接是 schema/property dict（来自 definitions 展开）
                    param_name = param.get('name')
                    param_in = param.get('in')
                    schema = param.get('schema') or {}
                    # 判断是否存在自定义的模型或对象
                    if isinstance(schema, dict) and '$ref' in schema:
                        ref = schema['$ref'].split('/')[-1]
                        # 如果在 definitions/components 中声明了参数属性，则不再盲目展开为扁平参数，
                        # 而是把整个 schema 作为 body（如果是 body）或保留单个参数（如果是 query/path）
                        if param_in in ('body', 'formData') or param_name == 'body':
                            # 构建整体 body 示例，交给 fill_parameters 处理覆盖逻辑
                            param_info.append({
                                'name': 'body',
                                'in': param_in or 'body',
                                'type': None,
                                'schema': schema
                            })
                        else:
                            # 对于非 body 的复杂 schema，尝试展开为子属性（兼容旧行为）
                            if ref in definitions:
                                model = definitions[ref]
                                if isinstance(model, dict):
                                    for prop_name, prop_details in model.get('properties', {}).items():
                                        param_info.append({
                                            'name': prop_name,
                                            'in': param_in or 'body',
                                            'type': prop_details.get('type')
                                        })
                            else:
                                # 如果找不到 ref 的模型，则保留原始 ref 参数
                                param_info.append({
                                    'name': param_name or ref,
                                    'in': param_in or 'body',
                                    'type': None
                                })
                    else:
                        # 如果 param 本身带有 schema 且 schema 有 properties（例如 inline schema）
                        if isinstance(schema, dict) and 'properties' in schema:
                            # 把 inline 的复杂类型作为整体 body（以便构建嵌套示例）
                            if param_in in ('body', 'formData') or param_name == 'body':
                                param_info.append({
                                    'name': 'body',
                                    'in': param_in or 'body',
                                    'type': None,
                                    'schema': schema
                                })
                            else:
                                # 非 body 的情况下，仍然尝试展开为多个参数
                                for prop_name, prop_details in schema.get('properties', {}).items():
                                    param_info.append({
                                        'name': prop_name,
                                        'in': param_in or 'body',
                                        'type': prop_details.get('type')
                                    })
                        else:
                            # 普通参数（query/path/formData/header）
                            param_type = param.get('type')
                            # fallback: if no name but schema contains $ref properties, expand
                            if not param_name and isinstance(schema, dict) and '$ref' in schema:
                                ref = schema['$ref'].split('/')[-1]
                                if ref in definitions:
                                    model = definitions[ref]
                                    for prop_name, prop_details in model.get('properties', {}).items():
                                        param_info.append({
                                            'name': prop_name,
                                            'in': param_in or 'body',
                                            'type': prop_details.get('type')
                                        })
                                    continue
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

            # 生成发送的 Body 数据 (支持单次填充或多值组合填充)
            if multi:
                combos = generate_param_combinations(parameters, req_path, csv_params=csv_params)
            else:
                filled_single, new_url = fill_parameters(parameters, req_path, csv_params=csv_params)
                combos = [(filled_single, new_url)]

            headers = {}

            if 'application/json' in consumes:
                headers = {'Content-Type': 'application/json'}

            for filled_params, new_url in combos:
                # 统一把成功判定改为任何非黑名单都写到 CSV；黑名单状态则写日志
                try:
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
                    logger.error(f'[-] Request error for {method} {new_url}: {e}')

    except Exception as e:
        logger.error(f'[-] {url} error info {e}')

def run(target, csv_params=None, multi=False):
    """
    执行程序
    """
    url_type = check_page(target)
    if url_type == 1:
        logger.success('working on {}'.format(target), 'type: source')
        go_resources(target, csv_params=csv_params, multi=multi)
    elif url_type == 2:
        logger.success('working on {}'.format(target), 'type: api-docs')
        go_api_docs(target, csv_params=csv_params, multi=multi)
    else:
        logger.success('working on {}'.format(target), 'type: html')
        go_swagger_html(target, csv_params=csv_params, multi=multi)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', dest='target_url', help='resource 地址 or api 文档地址 or swagger 首页地址')
    parser.add_argument('-f', '--file', dest='url_file', help='批量测试')
    parser.add_argument('-c', '--csv-params', dest='csv_params', help='CSV 参数文件路径（key,value），优先使用 CSV 中的参数值覆盖 api-docs 参数值（空值会被忽略）')
    parser.add_argument('-m', '--multi', dest='multi', action='store_true', help='启用多值组合尝试：当 CSV 中某参数有多个值时，尝试所有值；当有多个参数有多个值时，尝试所有笛卡尔积组合（默认关闭，保持原行为只使用每个参数第一个 CSV 值）')
    args = parser.parse_args()

    logger.add('debug.log', format='{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}')

    csv_params_map = {}
    if args.csv_params:
        csv_params_map = read_csv_values(args.csv_params)
        logger.info(f'[+] loaded csv params: {len(csv_params_map)} keys from {args.csv_params}')

    if args.target_url:
        run(args.target_url, csv_params=csv_params_map, multi=args.multi)
    elif args.url_file:
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f.readlines()]
        for target_url in urls:
            print(target_url)
            run(target_url, csv_params=csv_params_map, multi=args.multi)