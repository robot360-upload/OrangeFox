



SPDX-License-Identifier: Apache-2.0

Copyright (C) 2026 OrangeFox Recovery Project

Device identifier

PRODUCT_RELEASE_NAME := gta4l
DEVICE_PATH := device/samsung/gta4l

Inherit the base Android products

$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base_telephony.mk)

Inherit from the gta4l device

$(call inherit-product, $(DEVICE_PATH)/device.mk)

Inherit TWRP/OrangeFox common configuration

$(call inherit-product, vendor/twrp/config/common.mk)

Device identity

PRODUCT_DEVICE := gta4l
PRODUCT_NAME := twrp_gta4l
PRODUCT_BRAND := samsung
PRODUCT_MODEL := SM-T505
PRODUCT_MANUFACTURER := samsung

PRODUCT_GMS_CLIENTID_BASE := android-samsung-ss
