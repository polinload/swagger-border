#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
改进版：在 V5 的基础上添加“针对性回退查找”以补回常见被漏的字段（apiName/apiId/.../accessAddress/colId 等）。
输出文件名：extracted_YYYYMMDD_HHMMSS.csv（UTF-8）
用法：python extract_params_fix.py 2.txt

修改点：
- 在输出 CSV 时，忽略参数值为空字符串（strip() 为空）或为 None 的条目，不把它们写入 CSV。
- 摘要打印也只显示非空值的前几项。
"""
from collections import defaultdict
import json, re, argparse, csv, sys
from datetime import datetime

# 编码候选（同 V5 逻辑）
CANDIDATE_ENCODINGS = ["utf-8", "utf-8-sig", "gb18030", "gbk", "gb2312", "big5", "cp1252", "latin1"]

def score_text_for_chinese(text):
    num_chinese = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    num_replace = text.count("\ufffd") + text.count("�")
    printable = sum(1 for ch in text if ch.isprintable()) / max(1, len(text))
    return num_chinese * 10 - num_replace * 50 + int(printable * 10)

def choose_best_decoding(raw):
    best_text = None; best_enc = None; best_score = -10**9
    for enc in CANDIDATE_ENCODINGS:
        try:
            txt = raw.decode(enc, errors="replace")
        except Exception:
            continue
        score = score_text_for_chinese(txt)
        if score > best_score:
            best_score = score; best_text = txt; best_enc = enc
    # 额外尝试 latin1->utf-8 重解码修复
    try:
        s_latin = raw.decode("latin1", errors="strict")
        redecoded = s_latin.encode("latin1", errors="replace").decode("utf-8", errors="replace")
        score = score_text_for_chinese(redecoded)
        if score > best_score:
            best_score = score; best_text = redecoded; best_enc = "latin1->utf-8"
    except Exception:
        pass
    if best_text is None:
        best_text = raw.decode("utf-8", errors="ignore"); best_enc = "utf-8(ignore)"
    return best_text, best_enc

# 查找平衡 JSON 段（同 V5）
def find_json_segments(text):
    segments=[]; stack=[]; start=None
    for i,ch in enumerate(text):
        if ch in '{[':
            if not stack: start=i
            stack.append(ch)
        elif ch in '}]':
            if stack:
                top=stack[-1]
                if (top=='{' and ch=='}') or (top=='[' and ch==']'):
                    stack.pop()
                    if not stack and start is not None:
                        segments.append((start,i+1,text[start:i+1])); start=None
                else:
                    stack=[]; start=None
            else:
                start=None
    return segments

def extract_from_json_obj(obj, found):
    if isinstance(obj, dict):
        for k,v in obj.items():
            if isinstance(k,str):
                if isinstance(v,(str,int,float,bool)) or v is None:
                    found[k].append("" if v is None else str(v))
                else:
                    extract_from_json_obj(v, found)
    elif isinstance(obj, list):
        for it in obj:
            extract_from_json_obj(it, found)

# 回退正则（保守）
RE_QUOTED = re.compile(r'([A-Za-z_\u4e00-\u9fff][A-Za-z0-9_\u4e00-\u9fff\-]*)\s*:\s*"([^"]*?)"', re.UNICODE)
RE_UNQUOTED = re.compile(r'([A-Za-z_\u4e00-\u9fff][A-Za-z0-9_\u4e00-\u9fff\-]*)\s*:\s*([A-Za-z0-9_\-\/\.\u4e00-\u9fff]+)', re.UNICODE)

# 额外要重点补回的字段名列表（可按需扩充）
KEYS_OF_INTEREST = [
    "apiName","apiCode","apiId","apiCatalogue","apiDescribe","apiType","apiVersion",
    "accessAddress","accessToken","requestHead","colId","apiParams","apiBodys","requestMethod"
]

def extract_key_values(text):
    found = defaultdict(list)
    # 1) JSON 段解析优先
    segs = find_json_segments(text)
    used_ranges = []
    for s,e,seg in segs:
        try:
            parsed = json.loads(seg)
        except Exception:
            try:
                cleaned = seg.replace('\t',' ').replace('\r',' ').replace('\n',' ')
                parsed = json.loads(cleaned)
            except Exception:
                parsed = None
        if parsed is not None:
            extract_from_json_obj(parsed, found)
            used_ranges.append((s,e))
    # 2) 剩余文本做保守正则提取
    if used_ranges:
        pieces=[]; last=0
        for s,e in sorted(used_ranges):
            pieces.append(text[last:s]); last=e
        pieces.append(text[last:])
        remaining = "\n".join(pieces)
    else:
        remaining = text
    for k,v in RE_QUOTED.findall(remaining):
        if v!='': found[k].append(v)
    for k,v in RE_UNQUOTED.findall(remaining):
        if v!='': found[k].append(v)
    # 3) 关键字段的全局宽松搜索（补回被前两步漏掉的重要字段）
    for key in KEYS_OF_INTEREST:
        # 匹配 "key": "value" 或 key:"value" 或 key: value
        pat = re.compile(r'"?' + re.escape(key) + r'"?\s*:\s*"?([^",\]\}\n\r]+)"?', re.IGNORECASE)
        for m in pat.findall(text):
            val = m.strip()
            if val=='' or val.lower() in ('null','none'):
                # 记录空字符串以保留 null 信息（但后续输出会忽略空值）
                found[key].append('' if val.lower() in ('null','none') else val)
            else:
                found[key].append(val)
    # 4) 去重保持顺序
    for k in list(found.keys()):
        seen=set(); uniq=[]
        for v in found[k]:
            if v not in seen:
                seen.add(v); uniq.append(v)
        found[k]=uniq
    return found

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs="?", default="2.txt")
    parser.add_argument("--filter","-f",default=None)
    args = parser.parse_args()

    try:
        raw = open(args.file,"rb").read()
    except Exception as e:
        print("读取文件失败：",e,file=sys.stderr); sys.exit(2)

    text,enc = choose_best_decoding(raw)
    kv = extract_key_values(text)
    keys = sorted(kv.keys(), key=lambda s:s.lower())
    if args.filter:
        f=args.filter.lower(); keys=[k for k in keys if f in k.lower()]
    if not keys:
        print("未找到键。已选解码:",enc); return

    out = f"extracted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    written = 0
    with open(out,"w",encoding="utf-8",newline="") as f:
        w=csv.writer(f); w.writerow(["key","value"])
        for k in keys:
            for v in kv[k]:
                # 忽略 None 或 仅包含空白字符的值
                if v is None:
                    continue
                if isinstance(v, str) and v.strip() == "":
                    continue
                # 非空则写入
                w.writerow([k,v])
                written += 1

    print("解码:",enc," 输出:",out, " 写入条目:", written)
    # 摘要打印前20个键（只显示非空的值）
    for k in keys[:20]:
        vals = [vv for vv in kv[k] if not (vv is None or (isinstance(vv,str) and vv.strip()==''))]
        print(k, ":", vals[:3] if len(vals)>1 else vals)

if __name__=="__main__":
    main()