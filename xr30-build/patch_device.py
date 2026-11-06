#!/usr/bin/env python3
"""把 cmcc_xr30 设备定义追加进 target/linux/mediatek/image/filogic.mk。

为什么需要：immortalwrt 上游没有 XR30，实机可用的 itb 是社区作者
「基于 RAX3000M 改名」做的。这里照抄 cmcc_rax3000m_common 的全部镜像参数
（IMAGES := sysupgrade.itb / external-static-with-rootfs / KERNEL_IN_UBI），
只把 DTS 换成 mt7981b-cmcc-xr30（compatible=cmcc,xr30、两盏灯）。
"""
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
MK = os.path.join(ROOT, "target/linux/mediatek/image/filogic.mk")

BLOCK = """
# ---- BUER-WRT: CMCC XR30 (基于 RAX3000M，FIT/.itb，ubootmod 布局) ----
define Device/cmcc_xr30
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := XR30
  DEVICE_DTS := mt7981b-cmcc-xr30
  SUPPORTED_DEVICES := cmcc,xr30 cmcc,rax3000m
  DEVICE_DTS_OVERLAY := mt7981b-cmcc-rax3000m-emmc mt7981b-cmcc-rax3000m-nand
  DEVICE_DTS_DIR := ../dts
  DEVICE_DTC_FLAGS := --pad 4096
  DEVICE_DTS_LOADADDR := 0x43f00000
  DEVICE_PACKAGES := kmod-mt7915e kmod-mt7981-firmware mt7981-wo-firmware kmod-usb3 \\
\tautomount f2fsck mkf2fs
  KERNEL_LOADADDR := 0x44000000
  KERNEL := kernel-bin | gzip
  KERNEL_INITRAMFS := kernel-bin | lzma | \\
\tfit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd | pad-to 64k
  KERNEL_INITRAMFS_SUFFIX := -recovery.itb
  KERNEL_IN_UBI := 1
  UBOOTENV_IN_UBI := 1
  IMAGES := sysupgrade.itb
  IMAGE_SIZE := $$(shell expr 64 + $$(CONFIG_TARGET_ROOTFS_PARTSIZE))m
  IMAGE/sysupgrade.itb := append-kernel | \\
\tfit gzip $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb external-static-with-rootfs | \\
\tpad-rootfs | append-metadata
endef
TARGET_DEVICES += cmcc_xr30
"""

src = open(MK, encoding="utf-8").read()
if "Device/cmcc_xr30\n" in src:
    print("设备定义已存在，跳过")
    sys.exit(0)

open(MK, "a", encoding="utf-8").write(BLOCK)
print("已追加 Device/cmcc_xr30 到", MK)
