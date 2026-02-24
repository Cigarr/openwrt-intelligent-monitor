<p align="center">
  <h1 align="center">OpenWrt 智能监控（青龙面板专属）</h1>
</p>

<p align="center">
  <a href="https://www.python.org/" target="_blank">
    <img src="https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.x">
  </a>
  <a href="https://openwrt.org/" target="_blank">
    <img src="https://img.shields.io/badge/Platform-OpenWrt-green?style=flat-square&logo=openwrt&logoColor=white" alt="OpenWrt">
  </a>
  <a href="https://github.com/whyour/qinglong" target="_blank">
    <img src="https://img.shields.io/badge/青龙面板-适配版-teal?style=flat-square&logo=docker&logoColor=white" alt="青龙面板适配">
  </a>
  <a href="https://github.com/Cigarr/openwrt-intelligent-monitor" target="_blank">
    <img src="https://img.shields.io/badge/资源占用-CPU≤5%25%20%7C%20内存≤20MB-lightgrey?style=flat-square&logo=serverless&logoColor=white" alt="低资源占用">
  </a>
</p>

---

## ✨ 核心功能
| 图标 | 功能描述 |
| :--- | :--- |
| 🕒 | **8小时周期推送**：单次运行8小时，结束自动发企业微信汇总 |
| 📶 | **阶梯式检测**：正常30分钟/次，异常5分钟/次，连续正常延至45分钟 |
| 🛡️ | **异常防抖**：连续2次异常才记录，避免网络抖动误报 |
| ⚡ | **并行检测**：3线程并发，DNS缓存5分钟，CPU占用≤5% |
| 🗑️ | **日志自动清理**：推送成功10分钟后删除本次日志，防磁盘堆积 |
| 🛑 | **终止兜底**：手动停止/异常崩溃，立即推送当前结果 |

---

## 🎯 适用场景
- OpenWrt / 斐讯N1 旁路由监控
- NoIP 动态域名解析状态检测
- 内网服务（NAS/服务器）端口存活监控
- 青龙面板 Docker 环境 7×24h 无人值守

---

## 🚀 青龙一键部署
1. 订阅管理 → 新增订阅
   - 名称：OpenWrt 智能监控
   - 链接：`https://github.com/Cigarr/openwrt-intelligent-monitor.git`
   - 黑名单：`config.py`（**关键：防止更新覆盖配置**）
2. 运行订阅 → 自动生成定时任务（每8小时执行）
3. 编辑 `config.py` 填入企业微信信息+监控目标，即可启用

---

## 📱 通知预览（科技风）