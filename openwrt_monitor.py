# -*- coding: utf-8 -*-
"""
OpenWrt 智能监控脚本
功能：阶梯式检测、异常防抖、并行检测、企业微信汇总通知
优化：低占用、抗延迟、不误报
"""

import requests
import socket
import time
import threading
import traceback
import gc
from concurrent.futures import ThreadPoolExecutor

# ====================== 【用户配置区】======================
CORP_ID = "wwxxxxxxxxxxxxxxx"
CORP_SECRET = "xxxxxxxxxxxxxxxxxx"
AGENT_ID = 1000002
TO_USER = "@all"

# 检测域名（支持 NoIP）
TEST_DOMAINS = [
    "www.baidu.com",
    "yourname.ddns.net",
    "www.aliyun.com"
]

# 检测内网 IP:端口
TEST_IP_PORTS = [
    "192.168.0.188:5003",
    "192.168.0.1:80"
]

# 监控策略
DURATION_RUN = 28800
INTERVAL_NORMAL = 1800
INTERVAL_ABNORMAL = 300
DEBOUNCE_TIMES = 2

TIMEOUT_DOMAIN = 2.0
TIMEOUT_IP_PORT = 1.5
MAX_WORKERS = 3
# ==========================================================

detect_history = {
    "total_times": 0,
    "abnormal_times": 0,
    "domain_abnormal": [],
    "ip_port_abnormal": [],
    "last_abnormal_time": "",
    "consecutive_abnormal": 0
}

stop_flag = False
current_interval = INTERVAL_NORMAL
last_detect_result = {"domain": {}, "ip_port": {}}

def print_log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def check_single_domain(domain):
    def _resolve():
        try:
            if domain in last_detect_result["domain"]:
                ok, msg = last_detect_result["domain"][domain]
                if ok:
                    return ok, msg
            ip = socket.gethostbyname(domain)
            s = socket.socket()
            s.settimeout(TIMEOUT_DOMAIN)
            conn_ok = s.connect_ex((ip, 80)) == 0
            s.close()
            if conn_ok:
                msg = f"{domain} 解析+连通正常"
            else:
                msg = f"{domain} 解析成功，但80端口不通"
            last_detect_result["domain"][domain] = (True, msg)
            return True, msg
        except socket.gaierror:
            msg = f"{domain} 解析失败（NoIP未更新）"
            last_detect_result["domain"][domain] = (False, msg)
            return False, msg
        except Exception as e:
            msg = f"{domain} 异常：{str(e)}"
            last_detect_result["domain"][domain] = (False, msg)
            return False, msg

    ok, msg = _resolve()
    if ok:
        return ok, msg
    time.sleep(0.3)
    return _resolve()

def check_single_ip_port(ip_port):
    def _connect():
        try:
            if ip_port in last_detect_result["ip_port"]:
                ok, msg = last_detect_result["ip_port"][ip_port]
                if ok:
                    return ok, msg
            ip, port = ip_port.split(":")
            port = int(port)
            s = socket.socket()
            s.settimeout(TIMEOUT_IP_PORT)
            s.connect((ip, port))
            s.close()
            msg = f"{ip_port} 连接成功"
            last_detect_result["ip_port"][ip_port] = (True, msg)
            return True, msg
        except Exception as e:
            msg = f"{ip_port} 失败：{str(e)}"
            last_detect_result["ip_port"][ip_port] = (False, msg)
            return False, msg

    ok, msg = _connect()
    if ok:
        return ok, msg
    time.sleep(0.3)
    return _connect()

def detect_once():
    global current_interval
    detect_history["total_times"] += 1
    print_log(f"===== 第 {detect_history['total_times']} 次检测 =====")

    domain_ok = True
    domain_errs = []
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        results = list(executor.map(check_single_domain, TEST_DOMAINS))
    for ok, msg in results:
        print_log(msg)
        if not ok:
            domain_ok = False
            domain_errs.append(msg)

    ip_port_ok = True
    ip_port_errs = []
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        results = list(executor.map(check_single_ip_port, TEST_IP_PORTS))
    for ok, msg in results:
        print_log(msg)
        if not ok:
            ip_port_ok = False
            ip_port_errs.append(msg)

    if not domain_ok or not ip_port_ok:
        detect_history["consecutive_abnormal"] += 1
        print_log(f"⚠️ 连续异常：{detect_history['consecutive_abnormal']}")
        if detect_history["consecutive_abnormal"] >= DEBOUNCE_TIMES:
            detect_history["abnormal_times"] += 1
            detect_history["last_abnormal_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
            detect_history["domain_abnormal"].extend(domain_errs)
            detect_history["ip_port_abnormal"].extend(ip_port_errs)
        current_interval = INTERVAL_ABNORMAL
    else:
        detect_history["consecutive_abnormal"] = 0
        current_interval = INTERVAL_NORMAL
    gc.collect()

def detect_loop():
    start_time = time.time()
    while not stop_flag:
        detect_once()
        if time.time() - start_time >= DURATION_RUN:
            break
        print_log(f"等待 {current_interval // 60} 分钟")
        time.sleep(current_interval)

def get_qywx_token():
    try:
        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORP_ID}&corpsecret={CORP_SECRET}"
        resp = requests.get(url, timeout=10).json()
        return resp.get("access_token") if resp.get("errcode") == 0 else None
    except Exception:
        return None

def send_summary():
    token = get_qywx_token()
    if not token:
        return

    def fmt(items):
        if not items:
            return "  无"
        return "\n".join(f"    • {x}" for x in list(set(items)))

    now = time.strftime('%Y-%m-%d %H:%M:%S')
    start_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - DURATION_RUN))

    if detect_history["abnormal_times"] == 0:
        content = f"""
🟢 OpenWrt 8小时监控 · 全部正常
──────────────────────────────
📊 总检测：{detect_history['total_times']} 次
📡 域名正常
🔌 端口正常
🕒 {start_time_str} ~ {now}
""".strip()
    else:
        content = f"""
🔴 OpenWrt 8小时监控 · 出现异常
──────────────────────────────
📊 异常次数：{detect_history['abnormal_times']}
🕒 最后异常：{detect_history['last_abnormal_time']}

📡 域名异常：
{fmt(detect_history['domain_abnormal'])}

🔌 端口异常：
{fmt(detect_history['ip_port_abnormal'])}

🕒 {start_time_str} ~ {now}
""".strip()

    try:
        send_url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={token}"
        data = {
            "touser": TO_USER,
            "msgtype": "text",
            "agentid": AGENT_ID,
            "text": {"content": content}
        }
        requests.post(send_url, json=data, timeout=10)
        print_log("✅ 企业微信汇总发送成功")
    except Exception as e:
        print_log(f"❌ 发送失败：{e}")

def main():
    global stop_flag
    print_log("🚀 OpenWrt 智能监控启动")
    t = threading.Thread(target=detect_loop, daemon=True)
    t.start()
    time.sleep(DURATION_RUN)
    stop_flag = True
    t.join()
    send_summary()
    print_log("🏁 8小时监控周期结束")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()