#
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 GTA4L OrangeFox contributors
#
# Device-specific settings for Samsung Galaxy Tab A7 LTE (SM-T505).
# Shared SM6115/Bengal kernel and verified boot-image parameters are inherited
# from the current LineageOS gta4l-common tree; do not duplicate them here.
#

DEVICE_PATH := device/samsung/gta4l

-include device/samsung/gta4l-common/BoardConfigCommon.mk

# Device identity
TARGET_OTA_ASSERT_DEVICE := gta4l
TARGET_BOARD_NAME := P85943AA1
TARGET_BOOTIMAGE_BOARD_NAME := SRPTC24A004

# The v2 boot/recovery headers report board string SRPTC24A004.
BOARD_MKBOOTIMG_ARGS += --board $(TARGET_BOOTIMAGE_BOARD_NAME)

# Dynamic partition sizes from the current LineageOS gta4l device tree.
BOARD_GTA4L_DYNAMIC_PARTITIONS_SIZE := 5750390784
BOARD_SUPER_PARTITION_SIZE := 5754585088

# Use the recovery-specific TWRP/OrangeFox fstab, not Android fs_mgr fstab.
TARGET_RECOVERY_FSTAB := $(DEVICE_PATH)/recovery.fstab

# Verified from boot.img and recovery.img:
#   header version       = 2
#   page size            = 4096
#   kernel load address  = 0x00008000 (kernel offset)
#   ramdisk load address = 0x20000000 (ramdisk offset)
#   tags address         = 0x01E00000
#   DTB load address     = 0x01F00000
# The common BoardConfigCommon.mk already defines these values, along with
# BOARD_KERNEL_IMAGE_NAME := Image.gz, BOARD_INCLUDE_DTB_IN_BOOTIMG := true,
# BOARD_INCLUDE_RECOVERY_DTBO := true, and BOARD_KERNEL_SEPARATED_DTBO := true.
# Keep those inherited definitions in one place to avoid conflicting args.
