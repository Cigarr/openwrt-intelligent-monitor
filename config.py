# config.py - OpenWrt监控配置文件（仅改这个文件即可）
# ======================================
# 企业微信配置
CORP_ID = "wwxxxxxxxxxxxxxxx"       # 你的企业ID
CORP_SECRET = "xxxxxxxxxxxxxxxxxx"  # 你的应用Secret
AGENT_ID = 1000002                  # 你的应用AgentID
TO_USER = "@all"                    # 接收人：@all 或具体账号

# 检测目标配置
TEST_DOMAINS = [                    # 要监控的域名（含NoIP）
    "www.baidu.com",
    "yourname.ddns.net",
    "www.aliyun.com"
]
TEST_IP_PORTS = [                   # 要监控的IP+端口
    "192.168.0.188:5003",
    "192.168.0.1:80"
]

# 监控策略（可选修改）
DURATION_RUN = 28800                # 运行时长：8小时
INTERVAL_NORMAL = 1800              # 正常检测间隔：30分钟
INTERVAL_ABNORMAL = 300             # 异常检测间隔：5分钟
DEBOUNCE_TIMES = 2                  # 异常防抖次数
# ======================================