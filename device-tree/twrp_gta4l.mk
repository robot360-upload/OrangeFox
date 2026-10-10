#
# Copyright (C) 2026 GTA4L OrangeFox contributors
# SPDX-License-Identifier: Apache-2.0
#

PRODUCT_RELEASE_NAME := gta4l

# OrangeFox product configuration
$(call inherit-product, vendor/fox/config/common.mk)

# Existing GTA4L device configuration
$(call inherit-product, device/samsung/gta4l/device.mk)

# Device identifiers
PRODUCT_DEVICE := gta4l
PRODUCT_NAME := twrp_gta4l
PRODUCT_BRAND := samsung
PRODUCT_MODEL := SM-T505
PRODUCT_MANUFACTURER := samsung
PRODUCT_GMS_CLIENTID_BASE := android-samsung
