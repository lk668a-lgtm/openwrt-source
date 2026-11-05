# Buer-Wrt（CMCC XR30 NAND）

基于 `shiyu1314/openwrt-source` 的 `v25.12.6` 源码（就是你现在机器上跑的那套 25.12.2 同源），
设备 `cmcc_xr30-nand`，U-Boot 网页刷机。

## 与源码的差别
- 预装 `luci-app-tkproxy`（多线路分流，**不带卡密**，客户自己激活）
- 预装 `xray-core 26.3.27`（预编译 aarch64，不编 golang 工具链）
- 内嵌 Argon 3.1.2 主题（含 argon-config），默认深色
- 品牌 Buer-Wrt：banner / 主机名 / 系统描述 / 中文
- 管理地址 **http://192.168.8.1**，用户名 `root`，密码 `password`
- 无线 SSID `Buer-Wrt` / `Buer-Wrt-5G`，密码 `12345678`
- `SUPPORTED_DEVICES` 加了 `cmcc,xr30`，现有机器可直接 sysupgrade

## 出固件
Actions → `build-buer-wrt` → Run workflow（分支 buer-wrt），约 2–4 小时，
产物 `buer-wrt-cmcc_xr30-nand`。

## 刷机
U-Boot 网页（192.168.1.1）→ FIRMWARE UPDATE → 选 `*sysupgrade.bin` → Upload。
刷完后台 192.168.8.1，root / password。
