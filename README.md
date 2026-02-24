<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/Cigarr/openwrt-intelligent-monitor/logo.png" alt="OpenWrt 智能监控" width="200">
</p>

<h1 align="center">OpenWrt 智能监控（青龙面板专属）</h1>

<p align="center">
  <a href="https://github.com/Cigarr/openwrt-intelligent-monitor">
    <img src="https://img.shields.io/badge/OpenWrt-智能监控-v1.0-blue?style=for-the-badge&logo=openwrt&logoColor=white" alt="OpenWrt 智能监控">
  </a>
  <a href="https://github.com/Cigarr/openwrt-intelligent-monitor">
    <img src="https://img.shields.io/badge/青龙面板-适配版-00C7B7?style=for-the-badge&logo=docker&logoColor=white" alt="青龙面板适配版">
  </a>
  <a href="https://github.com/Cigarr/openwrt-intelligent-monitor">
    <img src="https://img.shields.io/badge/资源占用-CPU≤5%25%20%7C%20内存≤20MB-FB6B6B?style=for-the-badge&logo=serverless&logoColor=white" alt="资源占用">
  </a>
</p>

<div align="center">
  <h1 style="background: linear-gradient(90deg, #00C7B7, #64DFDF); -webkit-background-clip: text; color: transparent; font-size: 2em;">
    OpenWrt 智能监控脚本（青龙面板最终版）
  </h1>
</div>

---

## 🎯 核心功能（TECH CORE）
| 功能模块                | 技术特性                                                                 |
|-------------------------|--------------------------------------------------------------------------|
| 📊 周期化数据推送       | 8小时周期汇总推送企业微信（科技感可视化通知）                            |
| ⏱️ 动态阶梯检测         | 30分钟基准检测，异常缩至5分钟，连续正常延长至45分钟                     |
| 🛡️ 全链路数据保障       | 手动终止/异常中断/周期结束均推送结果，无数据丢失                        |
| 🧹 智能日志清理         | 推送成功后10分钟自动清理日志，释放Docker存储空间                        |
| ⚡ 极致资源管控         | CPU≤5%，内存≤20MB，适配青龙+Docker长期运行                             |

---

## 🔧 标准化部署流程（DEPLOYMENT）
<div style="background: rgba(0, 199, 183, 0.05); border-left: 4px solid #00C7B7; padding: 12px; border-radius: 4px;">
  <ol>
    <li><strong>添加订阅</strong>：青龙面板 → 订阅管理 → 添加订阅
      <ul style="margin: 8px 0 0 20px; color: #64748B;">
        <li>名称：OpenWrt智能监控</li>
        <li>类型：公开仓库</li>
        <li>链接：https://github.com/Cigarr/openwrt-intelligent-monitor.git</li>
        <li>分支：main</li>
        <li>黑名单：config.py（<span style="color: #EF4444;">关键！避免更新覆盖配置</span>）</li>
        <li>文件后缀：py</li>
      </ul>
    </li>
    <li><strong>生成任务</strong>：运行订阅后，青龙自动生成定时任务（每8小时执行）</li>
    <li><strong>配置初始化</strong>：修改config.py中的企业微信信息和检测目标即可使用</li>
  </ol>
</div>

---

## 🚀 底层核心优化（OPTIMIZATION）
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; margin-top: 10px;">
  <div style="background: rgba(100, 223, 223, 0.08); padding: 10px; border-radius: 6px; border: 1px solid #64DFDF;">
    <strong style="color: #00C7B7;">📡 DNS缓存优化</strong><br/>
    5分钟内复用解析结果，减少网络请求
  </div>
  <div style="background: rgba(100, 223, 223, 0.08); padding: 10px; border-radius: 6px; border: 1px solid #64DFDF;">
    <strong style="color: #00C7B7;">🚦 并行检测引擎</strong><br/>
    3线程并行，检测耗时≤2s
  </div>
  <div style="background: rgba(100, 223, 223, 0.08); padding: 10px; border-radius: 6px; border: 1px solid #64DFDF;">
    <strong style="color: #00C7B7;">♻️ 实时资源回收</strong><br/>
    实时GC，检测后立即释放线程/内存
  </div>
  <div style="background: rgba(100, 223, 223, 0.08); padding: 10px; border-radius: 6px; border: 1px solid #64DFDF;">
    <strong style="color: #00C7B7;">📜 日志生命周期管理</strong><br/>
    自动清理7天前日志，推送成功后10分钟清理本次日志
  </div>
  <div style="background: rgba(100, 223, 223, 0.08); padding: 10px; border-radius: 6px; border: 1px solid #64DFDF;">
    <strong style="color: #00C7B7;">🎯 异常防抖算法</strong><br/>
    2次异常后才记录，避免网络抖动误报
  </div>
</div>

---

<p align="right">
  <sub>适配青龙面板 + Docker 环境 | 轻量化高性能监控方案</sub>
</p>