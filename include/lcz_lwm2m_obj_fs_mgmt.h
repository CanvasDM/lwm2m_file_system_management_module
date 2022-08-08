/**
 * @file lcz_lwm2m_obj_fs_mgmt.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_LWM2M_OBJ_FS_MGMT_H__
#define __LCZ_LWM2M_OBJ_FS_MGMT_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr.h>
#include <zephyr/types.h>
#include <stddef.h>

#include "lcz_lwm2m.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/
/**
 * @brief Function to be called on LwM2M file system object operation.
 *
 * This callback function is used to notify the application about a pending file
 * read/write request and to authorise or deny it.
 *
 * @param path path of the file to query.
 * @param write true if write access is requested, false for read access
 *
 * @return true to allow the operation, false to deny
 */
typedef bool (*lcz_lwm2m_obj_fs_mgmt_permission_cb)(const char *path, bool write);

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/
/**
 * @brief Register file read/write access permission callback function.
 *
 * @param cb Callback function or NULL to disable.
 */
void lcz_lwm2m_obj_fs_mgmt_register_cb(lcz_lwm2m_obj_fs_mgmt_permission_cb cb);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_OBJ_FS_MGMT_H__ */
