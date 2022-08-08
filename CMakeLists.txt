#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#

if(CONFIG_LCZ_LWM2M_FS_MANAGEMENT)

zephyr_include_directories(include)
zephyr_sources(src/lcz_lwm2m_obj_fs_mgmt_directory.c)
zephyr_sources(src/lcz_lwm2m_obj_fs_mgmt_file.c)

endif()
