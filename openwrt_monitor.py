# -*- coding: utf-8 -*-
"""
OpenWrt 智能监控脚本（优化版）
- 支持手动终止（Ctrl+C/青龙停止）时发送当前检测结果
- 配置分离，仅需修改 config.py
- 异常中断兜底，保证通知必发
"""
import requests
import socket
import time
import threading
import traceback
import gc
import signal
from concurrent.futures import ThreadPoolExecutor

# 导入配置文件
import config

# ====================== 固定配置（无需修改）======================
TIMEOUT_DOMAIN = 2.0                # 域名检测超时
TIMEOUT_IP_PORT = 1.5               # IP端口检测超时
MAX_WORKERS = 3                     # 并行线程数
# 全局状态变量
detect_history = {
    "total_times": 0,
    "abnormal_times": 0,
    "domain_abnormal": [],
    "ip_port_abnormal": [],
    "last_abnormal_time": "",
    "consecutive_abnormal": 0
}
stop_flag = False
current_interval = config.INTERVAL_NORMAL
last_detect_result = {"domain": {}, "ip_port": {}}
# ===============================================================

def print_log(msg):
    """打印带时间戳的日志"""
    log_msg = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(log_msg)
    return log_msg

def signal_handler(signum, frame):
    """信号捕获函数：手动终止时触发"""
    print_log(f"⚠️  捕获到终止信号（信号码：{signum}），开始汇总当前检测结果...")
    global stop_flag
    stop_flag = True  # 停止检测循环
    send_summary(is_manual_stop=True)  # 发送终止时的汇总
    print_log("🏁 手动终止：当前检测结果已发送至企业微信")
    exit(0)  # 正常退出

# 注册终止信号监听（适配Windows/Linux/青龙）
try:
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # 进程终止（青龙停止）
except Exception as e:
    print_log(f"⚠️  系统不支持信号监听（Windows可能提示），不影响核心功能：{e}")

def check_single_domain(domain):
    """检测单个域名连通性（带重试）"""
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
                msg = f"{domain} 解析+连通正常（IP：{ip}）"
            else:
                msg = f"{domain} 解析成功（IP：{ip}），但80端口不通"
            last_detect_result["domain"][domain] = (True, msg)
            return True, msg
        except socket.gaierror:
            msg = f"{domain} 解析失败（NoIP未更新/域名失效）"
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
    """检测单个IP+端口连通性（带重试）"""
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
    """单次检测逻辑"""
    global current_interval
    detect_history["total_times"] += 1
    print_log(f"===== 第 {detect_history['total_times']} 次检测 =====")

    # 检测域名
    domain_ok = True
    domain_errs = []
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        results = list(executor.map(check_single_domain, config.TEST_DOMAINS))
    for ok, msg in results:
        print_log(msg)
        if not ok:
            domain_ok = False
            domain_errs.append(msg)

    # 检测IP端口
    ip_port_ok = True
    ip_port_errs = []
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        results = list(executor.map(check_single_ip_port, config.TEST_IP_PORTS))
    for ok, msg in results:
        print_log(msg)
        if not ok:
            ip_port_ok = False
            ip_port_errs.append(msg)

    # 更新异常状态
    if not domain_ok or not ip_port_ok:
        detect_history["consecutive_abnormal"] += 1
        print_log(f"⚠️  连续异常次数：{detect_history['consecutive_abnormal']}")
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
    """检测循环（8小时周期）"""
    start_time = time.time()
    start_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
    print_log(f"🚀 OpenWrt监控启动（周期：{config.DURATION_RUN//3600}小时），启动时间：{start_time_str}")
    
    while not stop_flag:
        detect_once()
        # 检查是否达到运行时长
        if time.time() - start_time >= config.DURATION_RUN:
            print_log(f"⏰ 达到预设运行时长（{config.DURATION_RUN//3600}小时），准备结束检测")
            break
        # 未终止则等待下一次检测
        if not stop_flag:
            print_log(f"⏳ 等待 {current_interval // 60} 分钟后进行下一次检测")
            time.sleep(current_interval)

def get_qywx_token():
    """获取企业微信Token"""
    try:
        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={config.CORP_ID}&corpsecret={config.CORP_SECRET}"
        resp = requests.get(url, timeout=10).json()
        if resp.get("errcode") == 0:
            return resp.get("access_token")
        else:
            print_log(f"❌ 获取企业微信Token失败：{resp}")
            return None
    except Exception as e:
        print_log(f"❌ 获取Token异常：{str(e)}")
        return None

def send_summary(is_manual_stop=False):
    """发送汇总通知（支持手动终止标记）"""
    token = get_qywx_token()
    if not token:
        print_log("❌ 企业微信Token获取失败，无法发送通知")
        return

    # 格式化异常列表（去重）
    def fmt(items):
        if not items:
            return "  无"
        return "\n".join(f"    • {x}" for x in list(set(items)))

    # 基础信息
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    start_time = time.time() - config.DURATION_RUN
    start_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))

    # 区分终止类型（手动/自动）
    if is_manual_stop:
        title = "🔴 OpenWrt监控 · 手动终止（当前结果汇总）"
    else:
        title = "🟢 OpenWrt监控 · 周期结束（完整结果汇总）"

    # 组装通知内容
    if detect_history["abnormal_times"] == 0:
        content = f"""
{title}
──────────────────────────────
📊 总检测次数：{detect_history['total_times']} 次
✅ 异常次数：0 次
📡 域名检测：全部正常
🔌 端口检测：全部正常
🕒 检测时段：{start_time_str} ~ {now}
""".strip()
    else:
        content = f"""
{title}
──────────────────────────────
📊 总检测次数：{detect_history['total_times']} 次
⚠️  异常次数：{detect_history['abnormal_times']} 次
🕒 最后异常：{detect_history['last_abnormal_time']}

📡 域名异常记录：
{fmt(detect_history['domain_abnormal'])}

🔌 端口异常记录：
{fmt(detect_history['ip_port_abnormal'])}

🕒 检测时段：{start_time_str} ~ {now}
""".strip()

    # 发送企业微信
    try:
        send_url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={token}"
        data = {
            "touser": config.TO_USER,
            "msgtype": "text",
            "agentid": config.AGENT_ID,
            "text": {"content": content},
            "safe": 0
        }
        resp = requests.post(send_url, json=data, timeout=10).json()
        if resp.get("errcode") == 0:
            print_log("✅ 企业微信通知发送成功")
        else:
            print_log(f"❌ 发送通知失败：{resp}")
    except Exception as e:
        print_log(f"❌ 发送通知异常：{str(e)}")

def main():
    """主函数"""
    try:
        # 启动检测循环
        detect_loop()
        # 自动结束时发送汇总（未被手动终止的情况）
        if not stop_flag:
            send_summary(is_manual_stop=False)
        print_log("🏁 OpenWrt监控正常结束")
    except Exception as e:
        # 捕获所有未处理异常，保证通知发送
        print_log(f"❌ 监控脚本异常终止：{str(e)}")
        traceback.print_exc()
        send_summary(is_manual_stop=True)  # 异常终止也发送汇总

if __name__ == "__main__":
    main()