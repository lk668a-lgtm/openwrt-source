#!/usr/bin/env python3
""".bin（原厂 MTK U-Boot / UBI 布局）版本的设备定义注入。

与 .itb 版（xr30-build/patch_device.py）的区别：
  .itb  —— FIT 布局，IMAGES := sysupgrade.itb，KERNEL_IN_UBI/UBOOTENV_IN_UBI
  .bin  —— 原厂 U-Boot 布局，IMAGES := sysupgrade.bin（sysupgrade-tar），
           不启用 KERNEL_IN_UBI（否则内核被打进 UBI，原厂 uboot 认不出）

两条产物的插件/包完全一致，只有镜像封装与启动布局不同。
"""
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
MK = os.path.join(ROOT, "target/linux/mediatek/image/filogic.mk")

BLOCK = """
# ---- BUER-WRT: CMCC XR30 (.bin，原厂 MTK U-Boot / UBI 布局) ----
define Device/cmcc_xr30-nand
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := XR30
  DEVICE_DTS := mt7981b-cmcc-xr30-nand
  SUPPORTED_DEVICES := cmcc,xr30-nand
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := kmod-mt7915e kmod-mt7981-firmware mt7981-wo-firmware kmod-usb3 \\
\tautomount f2fsck mkf2fs
  UBINIZE_OPTS := -E 5
  BLOCKSIZE := 128k
  PAGESIZE := 2048
  IMAGE_SIZE := 116736k
  IMAGES := sysupgrade.bin
  IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
  KERNEL = kernel-bin | lzma | \\
\tfit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb
  KERNEL_INITRAMFS = kernel-bin | lzma | \\
\tfit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd
endef
TARGET_DEVICES += cmcc_xr30-nand
"""

src = open(MK, encoding="utf-8").read()
if "define Device/cmcc_xr30-nand\n" in src:
    print("cmcc_xr30-nand 设备定义已存在，跳过")
    sys.exit(0)

open(MK, "a", encoding="utf-8").write(BLOCK)
print("已追加 Device/cmcc_xr30-nand 到", MK)
