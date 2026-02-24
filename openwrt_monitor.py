# -*- coding: utf-8 -*-
"""
OpenWrt 智能监控脚本（配置分离版）
配置文件：config.py（所有需要修改的参数都在这）
"""
import requests
import socket
import time
import threading
import traceback
import gc
from concurrent.futures import ThreadPoolExecutor

# 导入配置文件（核心修改：从config.py读取参数）
import config

# ====================== 固定配置（无需修改）======================
TIMEOUT_DOMAIN = 2.0                # 域名检测超时
TIMEOUT_IP_PORT = 1.5               # IP端口检测超时
MAX_WORKERS = 3                     # 并行线程数
# ===============================================================

# 全局状态变量（无需修改）
detect_history = {
    "total_times": 0,
    "abnormal_times": 0,
    "domain_abnormal": [],
    "ip_port_abnormal": [],
    "last_abnormal_time": "",
    "consecutive_abnormal": 0
}
stop_flag = False
current_interval = config.INTERVAL_NORMAL  # 从配置读取
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

    # 从配置读取检测目标（核心修改）
    domain_ok = True
    domain_errs = []
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        results = list(executor.map(check_single_domain, config.TEST_DOMAINS))
    for ok, msg in results:
        print_log(msg)
        if not ok:
            domain_ok = False
            domain_errs.append(msg)

    ip_port_ok = True
    ip_port_errs = []
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        results = list(executor.map(check_single_ip_port, config.TEST_IP_PORTS))
    for ok, msg in results:
        print_log(msg)
        if not ok:
            ip_port_ok = False
            ip_port_errs.append(msg)

    if not domain_ok or not ip_port_ok:
        detect_history["consecutive_abnormal"] += 1
        print_log(f"⚠️ 连续异常：{detect_history['consecutive_abnormal']}")
        if detect_history["consecutive_abnormal"] >= config.DEBOUNCE_TIMES:
            detect_history["abnormal_times"] += 1
            detect_history["last_abnormal_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
            detect_history["domain_abnormal"].extend(domain_errs)
            detect_history["ip_port_abnormal"].extend(ip_port_errs)
        current_interval = config.INTERVAL_ABNORMAL
    else:
        detect_history["consecutive_abnormal"] = 0
        current_interval = config.INTERVAL_NORMAL
    gc.collect()

def detect_loop():
    start_time = time.time()
    while not stop_flag:
        detect_once()
        if time.time() - start_time >= config.DURATION_RUN:
            break
        print_log(f"等待 {current_interval // 60} 分钟")
        time.sleep(current_interval)

def get_qywx_token():
    try:
        # 从配置读取企业微信参数（核心修改）
        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={config.CORP_ID}&corpsecret={config.CORP_SECRET}"
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
    start_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - config.DURATION_RUN))

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
            "touser": config.TO_USER,       # 从配置读取
            "msgtype": "text",
            "agentid": config.AGENT_ID,     # 从配置读取
            "text": {"content": content}
        }
        requests.post(send_url, json=data, timeout=10)
        print_log("✅ 企业微信汇总发送成功")
    except Exception as e:
        print_log(f"❌ 发送失败：{e}")

def main():
    global stop_flag
    print_log("🚀 OpenWrt 智能监控启动（配置分离版）")
    t = threading.Thread(target=detect_loop, daemon=True)
    t.start()
    time.sleep(config.DURATION_RUN)
    stop_flag = True
    t.join()
    send_summary()
    print_log("🏁 8小时监控周期结束")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()