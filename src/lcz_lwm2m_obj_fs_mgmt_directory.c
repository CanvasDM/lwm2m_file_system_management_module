/**
 * @file lcz_lwm2m_obj_directory.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */
/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(net_lwm2m_obj_fs_dir, CONFIG_LCZ_LWM2M_FS_MANAGEMENT_LOG_LEVEL);

#include <string.h>
#include <init.h>
#include <zephyr.h>
#include <device.h>
#include <fs/fs.h>
#include <stdint.h>
#include <lcz_lwm2m.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"
#include "file_system_utilities.h"
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
#include "encrypted_file_storage.h"
#endif

/**************************************************************************************************/
/* Global Constant, Macro and Type Definitions                                                    */
/**************************************************************************************************/
#define LWM2M_OBJECT_FS_MGMT_DIRECTORY_ID       27038

#define FS_MGMT_DIR_VERSION_MAJOR 1
#define FS_MGMT_DIR_VERSION_MINOR 0

#define FS_MGMT_DIR_PATH_ID 0
#define FS_MGMT_DIR_FILES_ID 1
#define FS_MGMT_DIR_SIZES_ID 2
#define FS_MGMT_DIR_ATTRIBUTES_ID 3
#define FS_MGMT_DIR_STATUS_ID 4
#define FS_MGMT_DIR_MAX_ID 5

#define MAX_STATUS_STRING 16
#define STATUS_OKAY "ok"
#define STATUS_ERROR "not found"

#define RES_INST_COUNT (FS_MGMT_DIR_MAX_ID - 3 + (CONFIG_LCZ_LWM2M_FS_MGMT_MAX_DIRECTORY_LIST * 3))

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static struct lwm2m_engine_obj fs_mgmt_dir;
static struct lwm2m_engine_obj_field fields[FS_MGMT_DIR_MAX_ID] = {
	OBJ_FIELD_DATA(FS_MGMT_DIR_PATH_ID, RW, STRING),
	OBJ_FIELD_DATA(FS_MGMT_DIR_FILES_ID, R, STRING),
	OBJ_FIELD_DATA(FS_MGMT_DIR_SIZES_ID, R, S32),
	OBJ_FIELD_DATA(FS_MGMT_DIR_ATTRIBUTES_ID, R, U16),
	OBJ_FIELD_DATA(FS_MGMT_DIR_STATUS_ID, R, STRING),
};

static struct lwm2m_engine_obj_inst inst;
static struct lwm2m_engine_res res[FS_MGMT_DIR_MAX_ID];
static struct lwm2m_engine_res_inst res_inst[RES_INST_COUNT];

static struct lwm2m_engine_res_inst *file_name_ris;
static struct lwm2m_engine_res_inst *file_size_ris;
static struct lwm2m_engine_res_inst *file_attributes_ris;

static char lwm2m_fs_mgmt_dir_active_path[CONFIG_LCZ_LWM2M_FS_MGMT_ACTIVE_PATH_LEN + 1];
static struct lwm2m_fs_mgmt_dir_entry_t {
	char name[CONFIG_LCZ_LWM2M_FS_MGMT_ACTIVE_PATH_LEN + 1];
	ssize_t size;
	uint16_t attributes;
} lwm2m_fs_mgmt_dir_files[CONFIG_LCZ_LWM2M_FS_MGMT_MAX_DIRECTORY_LIST];
static char lwm2m_fs_mgmt_dir_status[MAX_STATUS_STRING];

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static void set_status (const char *status_string);
static int cb_write_active_path(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
				uint8_t *data, uint16_t data_len, bool last_block,
				size_t total_size);
static struct lwm2m_engine_obj_inst *fs_mgmt_dir_create(uint16_t obj_inst_id);
static int lwm2m_fs_mgmt_dir_init(const struct device *dev);

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/**
 * @brief Set the status string
 *
 * @param[in] status_string New status string to set
 */
static void set_status (const char *status_string)
{
	if (strcmp(lwm2m_fs_mgmt_dir_status, status_string) != 0) {
		memset(lwm2m_fs_mgmt_dir_status, 0, sizeof(lwm2m_fs_mgmt_dir_status));
		strcpy(lwm2m_fs_mgmt_dir_status, status_string);
		NOTIFY_OBSERVER(LWM2M_OBJECT_FS_MGMT_DIRECTORY_ID, 0, FS_MGMT_DIR_STATUS_ID);
	}
}

/**
 * @brief Handle a write to the active path
 *
 * @param[in] obj_inst_id Object instance ID generating the callback.
 * @param[in] res_id Resource ID generating the callback.
 * @param[in] res_inst_id Resource instance ID generating the callback
 *                        (typically 0 for non-multi instance resources).
 * @param[in] data Pointer to data.
 * @param[in] data_len Length of the data.
 * @param[in] last_block Flag used during block transfer to indicate the last
 *                       block of data. For non-block transfers this is always
 *                       false.
 * @param[in] total_size Expected total size of data for a block transfer.
 *                       For non-block transfers this is 0.
 *
 * @returns 0 on success or <0 if an error occurred
 */
static int cb_write_active_path(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
				uint8_t *data, uint16_t data_len, bool last_block,
				size_t total_size)
{
	char abs_path[FSU_MAX_ABS_PATH_SIZE + 1];
	struct fs_dir_t dir = { 0 };
	struct fs_dirent entry = { 0 };
	int ret;
	int i;
	bool is_encrypted = false;

	/* Ensure that the input parameters are for our object */
	if (obj_inst_id != 0 || res_id != FS_MGMT_DIR_PATH_ID) {
		LOG_ERR("cb_write_active_path: invalid instance inputs %d %d %d", obj_inst_id,
			res_id, res_inst_id);
		return -EINVAL;
	}

	/* Make sure that we were passed some data */
	if (data == NULL || data_len == 0) {
		LOG_ERR("cb_write_active_path: no data provided");
		return -EINVAL;
	}

	/* Empty the current directory list */
	for (i = 0; i < CONFIG_LCZ_LWM2M_FS_MGMT_MAX_DIRECTORY_LIST; i++) {
		memset(lwm2m_fs_mgmt_dir_files[i].name, 0, sizeof(lwm2m_fs_mgmt_dir_files[0].name));
		lwm2m_fs_mgmt_dir_files[i].size = -1;
		lwm2m_fs_mgmt_dir_files[i].attributes = 0;
		file_name_ris[i].res_inst_id = RES_INSTANCE_NOT_CREATED;
		file_size_ris[i].res_inst_id = RES_INSTANCE_NOT_CREATED;
		file_attributes_ris[i].res_inst_id = RES_INSTANCE_NOT_CREATED;
	}

	/* Correct an empty path */
	if (lwm2m_fs_mgmt_dir_active_path[0] == '\0') {
		lwm2m_fs_mgmt_dir_active_path[0] = '/';
		lwm2m_fs_mgmt_dir_active_path[1] = '\0';
	}
	(void)fsu_build_full_name(abs_path, sizeof(abs_path), CONFIG_FSU_MOUNT_POINT,
				  lwm2m_fs_mgmt_dir_active_path);

#if defined(CONFIG_FSU_ENCRYPTED_FILES)
	/* Check to see if this is an encrypted file */
	is_encrypted = efs_is_encrypted_path(abs_path);

	/* Don't allow encrypted directory listings */
	if (is_encrypted) {
		/* Set the status string */
		set_status(STATUS_ERROR);
		return -EINVAL;
	}
#endif

	/* Read the new directory list */
	fs_dir_t_init(&dir);
	ret = fs_opendir(&dir, abs_path);
	if (ret == 0) {
		i = 0;
		while (ret >= 0 && i < CONFIG_LCZ_LWM2M_FS_MGMT_MAX_DIRECTORY_LIST) {
			ret = fs_readdir(&dir, &entry);
			if (ret < 0) {
				break;
			}

			/* Check for the end of the list */
			if (entry.name[0] == '\0') {
				break;
			}

			/* Copy the information into our array */
			strncpy(lwm2m_fs_mgmt_dir_files[i].name, entry.name,
				sizeof(lwm2m_fs_mgmt_dir_files[i].name));
			if (entry.type == FS_DIR_ENTRY_FILE) {
				lwm2m_fs_mgmt_dir_files[i].size = entry.size;
			} else {
				lwm2m_fs_mgmt_dir_files[i].size = -1;
			}
			lwm2m_fs_mgmt_dir_files[i].attributes = 0;

			/* Update the resource instances */
			file_name_ris[i].res_inst_id = i;
			file_name_ris[i].data_ptr = lwm2m_fs_mgmt_dir_files[i].name;
			file_name_ris[i].max_data_len = sizeof(lwm2m_fs_mgmt_dir_files[i].name);
			file_name_ris[i].data_len = strlen(lwm2m_fs_mgmt_dir_files[i].name);
			file_name_ris[i].data_flags = 0;

			file_size_ris[i].res_inst_id = i;
			file_size_ris[i].data_ptr = &(lwm2m_fs_mgmt_dir_files[i].size);
			file_size_ris[i].max_data_len = sizeof(lwm2m_fs_mgmt_dir_files[i].size);
			file_size_ris[i].data_len = file_size_ris[i].max_data_len;
			file_size_ris[i].data_flags = 0;

			file_attributes_ris[i].res_inst_id = i;
			file_attributes_ris[i].data_ptr = &(lwm2m_fs_mgmt_dir_files[i].attributes);
			file_attributes_ris[i].max_data_len =
				sizeof(lwm2m_fs_mgmt_dir_files[i].attributes);
			file_attributes_ris[i].data_len = file_attributes_ris[i].max_data_len;
			file_attributes_ris[i].data_flags = 0;

			i++;
		}
		(void)fs_closedir(&dir);

		/* Set the status string */
		set_status(STATUS_OKAY);
	} else {
		/* Set the status string */
		set_status(STATUS_ERROR);
	}

	/* Generate notifies for files, sizes, and attributes */
	NOTIFY_OBSERVER(LWM2M_OBJECT_FS_MGMT_DIRECTORY_ID, 0, FS_MGMT_DIR_FILES_ID);
	NOTIFY_OBSERVER(LWM2M_OBJECT_FS_MGMT_DIRECTORY_ID, 0, FS_MGMT_DIR_SIZES_ID);
	NOTIFY_OBSERVER(LWM2M_OBJECT_FS_MGMT_DIRECTORY_ID, 0, FS_MGMT_DIR_ATTRIBUTES_ID);

	return 0;
}

/**
 * @brief Create the instance of the file system management directory object
 *
 * @param[in] obj_inst_id Instance to create (ignored, assumed 0)
 *
 * @returns the created object or NULL on error
 */
static struct lwm2m_engine_obj_inst *fs_mgmt_dir_create(uint16_t obj_inst_id)
{
	int i;
	int j;

	/* Initialize our local data */
	memset(lwm2m_fs_mgmt_dir_active_path, 0, sizeof(lwm2m_fs_mgmt_dir_active_path));
	lwm2m_fs_mgmt_dir_active_path[0] = '/';
	memset(lwm2m_fs_mgmt_dir_status, 0, sizeof(lwm2m_fs_mgmt_dir_status));
	strcpy(lwm2m_fs_mgmt_dir_status, STATUS_OKAY);
	for (i = 0; i < CONFIG_LCZ_LWM2M_FS_MGMT_MAX_DIRECTORY_LIST; i++) {
		memset(lwm2m_fs_mgmt_dir_files[i].name, 0, sizeof(lwm2m_fs_mgmt_dir_files[0].name));
		lwm2m_fs_mgmt_dir_files[i].size = -1;
		lwm2m_fs_mgmt_dir_files[i].attributes = 0;
	}

	/* initialize instance resource data */
	i = 0;
	j = 0;
	init_res_instance(res_inst, ARRAY_SIZE(res_inst));
	INIT_OBJ_RES(FS_MGMT_DIR_PATH_ID, res, i, res_inst, j, 1, false, true,
		     lwm2m_fs_mgmt_dir_active_path, sizeof(lwm2m_fs_mgmt_dir_active_path), NULL,
		     NULL, NULL, cb_write_active_path, NULL);
	file_name_ris = &res_inst[j];
	INIT_OBJ_RES_MULTI_OPTDATA(FS_MGMT_DIR_FILES_ID, res, i, res_inst, j,
				   CONFIG_LCZ_LWM2M_FS_MGMT_MAX_DIRECTORY_LIST, false);
	file_size_ris = &res_inst[j];
	INIT_OBJ_RES_MULTI_OPTDATA(FS_MGMT_DIR_SIZES_ID, res, i, res_inst, j,
				   CONFIG_LCZ_LWM2M_FS_MGMT_MAX_DIRECTORY_LIST, false);
	file_attributes_ris = &res_inst[j];
	INIT_OBJ_RES_MULTI_OPTDATA(FS_MGMT_DIR_ATTRIBUTES_ID, res, i, res_inst, j,
				   CONFIG_LCZ_LWM2M_FS_MGMT_MAX_DIRECTORY_LIST, false);
	INIT_OBJ_RES_DATA(FS_MGMT_DIR_STATUS_ID, res, i, res_inst, j, lwm2m_fs_mgmt_dir_status,
			  sizeof(lwm2m_fs_mgmt_dir_status));

	inst.resources = res;
	inst.resource_count = i;

	return &inst;
}

/**************************************************************************************************/
/* SYS_INIT                                                                                       */
/**************************************************************************************************/
SYS_INIT(lwm2m_fs_mgmt_dir_init, APPLICATION, CONFIG_LCZ_LWM2M_FS_MGMT_INIT_PRIORITY);
static int lwm2m_fs_mgmt_dir_init(const struct device *dev)
{
	struct lwm2m_engine_obj_inst *obj_inst = NULL;
	int ret;

	/* Register the object */
	fs_mgmt_dir.obj_id = LWM2M_OBJECT_FS_MGMT_DIRECTORY_ID;
	fs_mgmt_dir.version_major = FS_MGMT_DIR_VERSION_MAJOR;
	fs_mgmt_dir.version_minor = FS_MGMT_DIR_VERSION_MINOR;
	fs_mgmt_dir.fields = fields;
	fs_mgmt_dir.field_count = ARRAY_SIZE(fields);
	fs_mgmt_dir.max_instance_count = 1;
	fs_mgmt_dir.create_cb = fs_mgmt_dir_create;
	lwm2m_register_obj(&fs_mgmt_dir);

	/* Auto create the only instance */
	ret = lwm2m_create_obj_inst(LWM2M_OBJECT_FS_MGMT_DIRECTORY_ID, 0, &obj_inst);
	if (ret < 0) {
		LOG_ERR("lwm2m_fs_mgmt_dir_init: Failed to create instance: %d", ret);
	}

	LOG_DBG("lwm2m_fs_mgmt_dir_init: Create LWM2M fs mgmt dir instance: 0");

	return ret;
}
