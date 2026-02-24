# OpenWrt 智能监控
🚀 低占用、高性能、抗延迟的家庭网络 / 服务器状态监控脚本

![Python](https://img.shields.io/badge/Python-3-blue)
![OpenWrt](https://img.shields.io/badge/Platform-OpenWrt-green)
![Monitor](https://img.shields.io/badge/Status-Monitor-orange)

## 功能亮点
- 🔁 **阶梯式检测**：正常 30 分钟，异常 5 分钟
- 🛡️ **异常防抖**：连续 2 次异常才判定，避免误报
- ⚡ **并行检测**：CPU 占用极低，速度快
- 📶 **支持 NoIP 动态域名**
- 💬 **企业微信 8 小时汇总通知**
- 📱 **科技感手机通知排版**
- 🐳 **青龙面板 / Linux 通用**

## 适用场景
- OpenWrt / N1 / 旁路由网络监控
- 内网服务器 / NAS / 端口存活监控
- NoIP 动态域名解析监控
- 家庭网络稳定性自动化巡检

## 快速使用
1. 安装依赖：
   ```bash
   pip install requests