DTS_DIR := $(DTS_DIR)/mediatek
DEVICE_VARS += SUPPORTED_TELTONIKA_DEVICES
DEVICE_VARS += SUPPORTED_TELTONIKA_HW_MODS

define Image/Prepare
	# For UBI we want only one extra block
	rm -f $(KDIR)/ubi_mark
	echo -ne '\xde\xad\xc0\xde' > $(KDIR)/ubi_mark
endef

define Build/fit-with-netgear-top-level-rootfs-node
	$(call Build/fit-its,$(1))
	$(TOPDIR)/scripts/gen_netgear_rootfs_node.sh $(KERNEL_BUILD_DIR)/root.squashfs > $@.rootfs
	awk '/configurations/ { system("cat $@.rootfs") } 1' $@.its > $@.its.tmp
	@mv -f $@.its.tmp $@.its
	@rm -f $@.rootfs
	$(call Build/fit-image,$(1))
endef

define Build/mt7981-bl2
	cat $(STAGING_DIR_IMAGE)/mt7981-$1-bl2.img >> $@
endef

define Build/mt7981-bl31-uboot
	cat $(STAGING_DIR_IMAGE)/mt7981_$1-u-boot.fip >> $@
endef

define Build/mt7986-bl2
	cat $(STAGING_DIR_IMAGE)/mt7986-$1-bl2.img >> $@
endef

define Build/mt7986-bl31-uboot
	cat $(STAGING_DIR_IMAGE)/mt7986_$1-u-boot.fip >> $@
endef

define Build/mt7987-bl2
	cat $(STAGING_DIR_IMAGE)/mt7987-$1-bl2.img >> $@
endef

define Build/mt7987-bl31-uboot
	cat $(STAGING_DIR_IMAGE)/mt7987_$1-u-boot.fip >> $@
endef

define Build/mt7988-bl2
	cat $(STAGING_DIR_IMAGE)/mt7988-$1-bl2.img >> $@
endef

define Build/mt7988-bl31-uboot
	cat $(STAGING_DIR_IMAGE)/mt7988_$1-u-boot.fip >> $@
endef

define Build/simplefit
	cp $@ $@.tmp 2>/dev/null || true
	ptgen -g -o $@.tmp -a 1 -l 1024 \
	-t 0x2e -N FIT		-p $(CONFIG_TARGET_ROOTFS_PARTSIZE)M@17k
	cat $@.tmp >> $@
	rm $@.tmp
endef

define Build/mt798x-gpt
	cp $@ $@.tmp 2>/dev/null || true
	ptgen -g -o $@.tmp -a 1 -l 1024 \
		$(if $(findstring sdmmc,$1), \
			-H \
			-t 0x83	-N bl2		-r	-p 4079k@17k \
		) \
			-t 0x83	-N ubootenv	-r	-p 512k@4M \
			-t 0x83	-N factory	-r	-p 2M@4608k \
			-t 0xef	-N fip		-r	-p 4M@6656k \
				-N recovery	-r	-p 32M@12M \
		$(if $(findstring sdmmc,$1), \
				-N install	-r	-p 20M@44M \
			-t 0x2e -N production		-p $(CONFIG_TARGET_ROOTFS_PARTSIZE)M@64M \
		) \
		$(if $(findstring emmc,$1), \
			-t 0x2e -N production		-p $(CONFIG_TARGET_ROOTFS_PARTSIZE)M@64M \
		)
	cat $@.tmp >> $@
	rm $@.tmp
endef

# Variation of the normal partition table to account
# for factory and mfgdata partition
#
# Keep fip partition at standard offset to keep consistency
# with uboot commands
define Build/mt7988-mozart-gpt
	cp $@ $@.tmp 2>/dev/null || true
	ptgen -g -o $@.tmp -a 1 -l 1024 \
			-t 0x83	-N ubootenv	-r	-p 512k@4M \
			-t 0xef	-N fip		  -r	-p 4M@6656k \
			-t 0x83	-N factory	-r	-p 8M@25M \
			-t 0x2e	-N mfgdata	-r	-p 8M@33M \
			-t 0xef -N recovery	-r	-p 32M@41M \
			-t 0x2e -N production		-p $(CONFIG_TARGET_ROOTFS_PARTSIZE)M@73M
	cat $@.tmp >> $@
	rm $@.tmp
endef

define Build/mstc-header
  $(eval version=$(word 1,$(1)))
  $(eval magic=$(word 2,$(1)))
  gzip -c $@ | tail -c8 > $@.crclen
  ( \
    printf "$(magic)"; \
    tail -c+5 $@.crclen; head -c4 $@.crclen; \
    dd if=/dev/zero bs=4 count=2; \
    printf "$(version)" | dd bs=56 count=1 conv=sync 2>/dev/null; \
    dd if=/dev/zero bs=$$((0x20000 - 0x84)) count=1 conv=sync 2>/dev/null | \
      tr "\0" "\377"; \
    cat $@; \
  ) > $@.new
  mv $@.new $@
endef

define Build/zyxel-nwa-fit-filogic
	$(TOPDIR)/scripts/mkits-zyxel-fit-filogic.sh \
		$@.its $@ "80 e1 81 e1 ff ff ff ff ff ff"
	PATH=$(LINUX_DIR)/scripts/dtc:$(PATH) mkimage -f $@.its $@.new
	@mv $@.new $@
endef

define Build/cetron-header
	$(eval magic=$(word 1,$(1)))
	$(eval model=$(word 2,$(1)))
	( \
		dd if=/dev/zero bs=856 count=1 2>/dev/null; \
		printf "$(model)," | dd bs=128 count=1 conv=sync 2>/dev/null; \
		md5sum $@ | cut -f1 -d" " | dd bs=32 count=1 2>/dev/null; \
		printf "$(magic)" | dd bs=4 count=1 conv=sync 2>/dev/null; \
		cat $@; \
	) > $@.tmp
	fw_crc=$$(gzip -c $@.tmp | tail -c 8 | od -An -N4 -tx4 --endian little | tr -d ' \n'); \
	printf "$$(echo $$fw_crc | sed 's/../\\x&/g')" | cat - $@.tmp > $@
	rm $@.tmp
endef

define Device/cmcc_rax3000m_common
  DEVICE_DTS_OVERLAY := mt7981b-cmcc-rax3000m-emmc mt7981b-cmcc-rax3000m-nand
  DEVICE_DTS_DIR := ../dts
  DEVICE_DTC_FLAGS := --pad 4096
  DEVICE_DTS_LOADADDR := 0x43f00000
  DEVICE_PACKAGES :=  kmod-usb3 \
	automount f2fsck mkf2fs
  KERNEL_LOADADDR := 0x44000000
  KERNEL := kernel-bin | gzip
  KERNEL_INITRAMFS := kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd | pad-to 64k
  KERNEL_INITRAMFS_SUFFIX := -recovery.itb
  KERNEL_IN_UBI := 1
  UBOOTENV_IN_UBI := 1
  IMAGES := sysupgrade.itb
  IMAGE_SIZE := $$(shell expr 64 + $$(CONFIG_TARGET_ROOTFS_PARTSIZE))m
  IMAGE/sysupgrade.itb := append-kernel | \
	fit gzip $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb external-static-with-rootfs | \
	pad-rootfs | append-metadata
endef

define Device/cmcc_rax3000m
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := RAX3000M
  DEVICE_DTS := mt7981b-cmcc-rax3000m
  $(call Device/cmcc_rax3000m_common)
endef
TARGET_DEVICES += cmcc_rax3000m

define Device/cmcc_rax3000me
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := RAX3000Me
  DEVICE_DTS := mt7981b-cmcc-rax3000me
  $(call Device/cmcc_rax3000m_common)
  DEVICE_DTS_OVERLAY += mt7981b-cmcc-rax3000me-nousb
endef
TARGET_DEVICES += cmcc_rax3000me

define Device/cmcc_rax3000m-emmc
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := RAX3000M (eMMC version)
  DEVICE_DTS := mt7981b-cmcc-rax3000m-emmc
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := kmod-usb3 e2fsprogs f2fsck mkf2fs \
	kmod-fs-ext4 tune2fs ethtool blockd blkid fdisk gdisk partx-utils
  KERNEL := kernel-bin | lzma | fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb
  KERNEL_INITRAMFS := kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd | pad-to 64k
  IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
endef
TARGET_DEVICES += cmcc_rax3000m-emmc

define Device/cmcc_rax3000m-nand
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := RAX3000M (NAND version)
  DEVICE_DTS := mt7981b-cmcc-rax3000m-nand
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := kmod-usb3
  UBINIZE_OPTS := -E 5
  BLOCKSIZE := 128k
  PAGESIZE := 2048
  IMAGE_SIZE := 116736k
  KERNEL_IN_UBI := 1
  IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
  KERNEL = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb
  KERNEL_INITRAMFS = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd
endef
TARGET_DEVICES += cmcc_rax3000m-nand

define Device/cmcc_rax3000m-256m-nand
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := RAX3000M (256M NAND version)
  DEVICE_DTS := mt7981b-cmcc-rax3000m-256m-nand
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := kmod-usb3
  UBINIZE_OPTS := -E 5
  BLOCKSIZE := 128k
  PAGESIZE := 2048
  IMAGE_SIZE := 116736k
  KERNEL_IN_UBI := 1
  IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
  KERNEL = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb
  KERNEL_INITRAMFS = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd
endef
TARGET_DEVICES += cmcc_rax3000m-256m-nand

define Device/cmcc_xr30-emmc
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := XR30 (eMMC version)
  DEVICE_DTS := mt7981b-cmcc-xr30-emmc
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := f2fsck mkf2fs
  KERNEL := kernel-bin | lzma | fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb
  KERNEL_INITRAMFS := kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd | pad-to 64k
  IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
endef
TARGET_DEVICES += cmcc_xr30-emmc

define Device/cmcc_xr30-nand
  DEVICE_VENDOR := CMCC
  DEVICE_MODEL := XR30 NAND
  DEVICE_VARIANT := (U-Boot mod)
  DEVICE_DTS := mt7981b-cmcc-xr30-nand
  SUPPORTED_DEVICES := cmcc,xr30-nand cmcc,xr30
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := kmod-usb3
  UBINIZE_OPTS := -E 5
  BLOCKSIZE := 128k
  PAGESIZE := 2048
  IMAGE_SIZE := 116736k
  KERNEL_IN_UBI := 1
  IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
  KERNEL = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb
  KERNEL_INITRAMFS = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd
endef
TARGET_DEVICES += cmcc_xr30-nand

define Device/openwrt_one
  DEVICE_VENDOR := OpenWrt
  DEVICE_MODEL := One
  DEVICE_DTS := mt7981b-openwrt-one
  DEVICE_DTS_DIR := ../dts
  DEVICE_DTC_FLAGS := --pad 4096
  DEVICE_DTS_LOADADDR := 0x43f00000
  DEVICE_PACKAGES :=  \
	kmod-rtc-pcf8563 kmod-usb3 kmod-phy-airoha-en8811h automount
  KERNEL_LOADADDR := 0x44000000
  KERNEL := kernel-bin | gzip
  KERNEL_INITRAMFS := kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd | pad-to 64k
  KERNEL_INITRAMFS_SUFFIX := .itb
  KERNEL_IN_UBI := 1
  UBOOTENV_IN_UBI := 1
  IMAGES := sysupgrade.itb
  IMAGE_SIZE := $$(shell expr 64 + $$(CONFIG_TARGET_ROOTFS_PARTSIZE))m
  IMAGE/sysupgrade.itb := append-kernel | fit gzip $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb external-with-rootfs | pad-rootfs | append-metadata
  ARTIFACTS := \
	nor-preloader.bin nor-bl31-uboot.fip \
	snand-preloader.bin snand-bl31-uboot.fip \
	factory.ubi snand-factory.bin nor-factory.bin
  ARTIFACT/nor-preloader.bin		:= mt7981-bl2 nor-ddr4
  ARTIFACT/nor-bl31-uboot.fip		:= mt7981-bl31-uboot openwrt_one-nor
  ARTIFACT/snand-preloader.bin		:= mt7981-bl2 spim-nand-ubi-ddr4
  ARTIFACT/snand-bl31-uboot.fip		:= mt7981-bl31-uboot openwrt_one-snand
  ARTIFACT/factory.ubi			:= ubinize-image fit squashfs-sysupgrade.itb
  ARTIFACT/snand-factory.bin		:= mt7981-bl2 spim-nand-ubi-ddr4 | pad-to 256k | \
					   mt7981-bl2 spim-nand-ubi-ddr4 | pad-to 512k | \
					   mt7981-bl2 spim-nand-ubi-ddr4 | pad-to 768k | \
					   mt7981-bl2 spim-nand-ubi-ddr4 | pad-to 1024k | \
					   ubinize-image fit squashfs-sysupgrade.itb
  ARTIFACT/nor-factory.bin		:= mt7981-bl2 nor-ddr4 | pad-to 256k | \
					   pad-to 1024k | \
					   mt7981-bl31-uboot openwrt_one-nor | pad-to 512k | \
					   append-image-stage initramfs.itb
  UBINIZE_OPTS := -E 5
  BLOCKSIZE := 128k
  PAGESIZE := 2048
  UBINIZE_PARTS := fip=:$(STAGING_DIR_IMAGE)/mt7981_openwrt_one-snand-u-boot.fip \
		   $(if $(IB),recovery=:$(STAGING_DIR_IMAGE)/mediatek-filogic-openwrt_one-initramfs.itb,\
			      recovery=:$(KDIR)/tmp/$$(KERNEL_INITRAMFS_IMAGE)) \
		   $(if $(wildcard $(TOPDIR)/openwrt-mediatek-filogic-openwrt_one-calibration.itb), calibration=:$(TOPDIR)/openwrt-mediatek-filogic-openwrt_one-calibration.itb)
endef
TARGET_DEVICES += openwrt_one
