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
#define LOG_MODULE_NAME net_lwm2m_obj_fs_file
#define LOG_LEVEL CONFIG_LCZ_LWM2M_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

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
#include "lcz_lwm2m_obj_fs_mgmt.h"

/**************************************************************************************************/
/* Global Constant, Macro and Type Definitions                                                    */
/**************************************************************************************************/
#define LWM2M_OBJECT_FS_MGMT_FILE_ID 27039

#define FS_MGMT_FILE_VERSION_MAJOR 1
#define FS_MGMT_FILE_VERSION_MINOR 0

#define FS_MGMT_FILE_PATH_ID 0
#define FS_MGMT_FILE_CONTENT_ID 1
#define FS_MGMT_FILE_DELETE_ID 2
#define FS_MGMT_FILE_CREATE_ID 3
#define FS_MGMT_FILE_EXECUTE_ID 4
#define FS_MGMT_FILE_UPLOAD_URL_ID 5 /* not implemented */
#define FS_MGMT_FILE_DOWNLOAD_URL_ID 6 /* not implemented */
#define FS_MGMT_FILE_CHMOD_ID 7 /* not implemented */
#define FS_MGMT_FILE_STATUS_ID 8
#define FS_MGMT_FILE_ERROR_ID 9
#define FS_MGMT_FILE_PROGRESS_ID 10 /* not implemented */
#define FS_MGMT_FILE_RESET_ID 11

#define FS_MGMT_FILE_MAX_ID 8

#define MAX_STATUS_STRING 16
#define STATUS_IDLE "idle"
#define ERROR_OKAY "none"
#define ERROR_NO_PERM "no permission"
#define ERROR_GENERIC "error"

#define RES_INST_COUNT (FS_MGMT_FILE_MAX_ID - 3)

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static struct lwm2m_engine_obj fs_mgmt_file;
static struct lwm2m_engine_obj_field fields[FS_MGMT_FILE_MAX_ID] = {
	OBJ_FIELD_DATA(FS_MGMT_FILE_PATH_ID, RW, STRING),
	OBJ_FIELD_DATA(FS_MGMT_FILE_CONTENT_ID, RW, OPAQUE),
	OBJ_FIELD_EXECUTE_OPT(FS_MGMT_FILE_DELETE_ID),
	OBJ_FIELD_EXECUTE_OPT(FS_MGMT_FILE_CREATE_ID),
	OBJ_FIELD_EXECUTE_OPT(FS_MGMT_FILE_EXECUTE_ID),
	OBJ_FIELD_DATA(FS_MGMT_FILE_STATUS_ID, R, STRING),
	OBJ_FIELD_DATA(FS_MGMT_FILE_ERROR_ID, R, STRING),
	OBJ_FIELD_EXECUTE_OPT(FS_MGMT_FILE_RESET_ID),
};

static struct lwm2m_engine_obj_inst inst;
static struct lwm2m_engine_res res[FS_MGMT_FILE_MAX_ID];
static struct lwm2m_engine_res_inst res_inst[RES_INST_COUNT];

static char lwm2m_fs_mgmt_file_active_path[CONFIG_LCZ_LWM2M_FS_MGMT_ACTIVE_PATH_LEN + 1];
static char lwm2m_fs_mgmt_file_status[MAX_STATUS_STRING];
static char lwm2m_fs_mgmt_file_error[MAX_STATUS_STRING];

static lcz_lwm2m_obj_fs_mgmt_permission_cb permission_cb = NULL;

/* The block buffer holds data used for active read and write operations */
static uint8_t block_buffer[CONFIG_LCZ_LWM2M_COAP_BLOCK_SIZE];

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static void set_error(const char *error_string);
static void *cb_read(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id, size_t *data_len);
static void *cb_read_block(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			   size_t offset, size_t read_len, uint8_t *data, size_t *data_len,
			   bool *last_block);
static void *cb_pre_write(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			  size_t *data_len);
static int cb_write_content(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			    uint8_t *data, uint16_t data_len, bool last_block, size_t total_size);
static int cb_exec_delete(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len);
static int cb_exec_create(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len);
static int cb_exec_execute(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len);
static int cb_exec_reset(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len);
static struct lwm2m_engine_obj_inst *fs_mgmt_file_create(uint16_t obj_inst_id);
static int lwm2m_fs_mgmt_file_init(const struct device *dev);

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/**
 * @brief Set the error string
 *
 * @param[in] error_string New error string to set
 */
static void set_error(const char *error_string)
{
	if (strcmp(lwm2m_fs_mgmt_file_error, error_string) != 0) {
		memset(lwm2m_fs_mgmt_file_error, 0, sizeof(lwm2m_fs_mgmt_file_error));
		strcpy(lwm2m_fs_mgmt_file_error, error_string);
		NOTIFY_OBSERVER(LWM2M_OBJECT_FS_MGMT_FILE_ID, 0, FS_MGMT_FILE_ERROR_ID);
	}
}

/**
 * @brief Read handler for the content resource
 *
 * This function needs to handle two different cases:
 *
 *     - If the file being read is smaller than the CoAP block size, the
 *       function should set *data_len to the size of the file being read AND
 *       the file data needs to be returned as a pointer from this function.
 *
 *     - If the file being read is larger than the CoAP block size, the
 *       function should set *data_len to the size of the file being read and
 *       the returned pointer is ignored.
 *
 * For simplicity's sake, this function will do the same thing in both cases, but
 * in the second case, the size of the returned data is limited to the size of the
 * CoAP block size.
 *
 * @param[in] obj_inst_id Object instance ID generating the callback.
 * @param[in] res_id Resource ID generating the callback.
 * @param[in] res_inst_id Resource instance ID generating the callback
 *                        (typically 0 for non-multi instance resources).
 * @param[out] data_len Length of the data buffer.
 *
 * @return Callback returns a pointer to the data buffer or NULL for failure.
 */
static void *cb_read(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id, size_t *data_len)
{
	char abs_path[FSU_MAX_ABS_PATH_SIZE + 1];
	struct fs_dirent entry;
	int ret;
	bool is_encrypted = false;
	size_t read_len;

	/* Validate the input parameters */
	if (obj_inst_id != 0 || res_id != FS_MGMT_FILE_CONTENT_ID || res_inst_id != 0 ||
	    data_len == NULL) {
		return NULL;
	}

	/* Default the data length to zero */
	*data_len = 0;

	/* Build the current path */
	(void)fsu_build_full_name(abs_path, sizeof(abs_path), CONFIG_FSU_MOUNT_POINT,
				  lwm2m_fs_mgmt_file_active_path);

#if defined(CONFIG_FSU_ENCRYPTED_FILES)
	/* Check to see if this is an encrypted file */
	is_encrypted = efs_is_encrypted_path(abs_path);
#endif

	/* Get permission to read this file */
	if (permission_cb != NULL) {
		if (permission_cb(abs_path, false) == false) {
			/* Permission denied */
			set_error(ERROR_NO_PERM);
			return NULL;
		}
	}

	/* Get the file size */
	ret = fs_stat(abs_path, &entry);
	if (ret < 0) {
		set_error(ERROR_GENERIC);
		return NULL;
	} else if (entry.type == FS_DIR_ENTRY_DIR) {
		set_error(ERROR_GENERIC);
		return NULL;
	} else {
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
		if (is_encrypted) {
			ret = efs_get_file_size(abs_path);
			if (ret >= 0) {
				*data_len = ret;
			} else {
				set_error(ERROR_GENERIC);
				return NULL;
			}
		} else
#endif
		{
			*data_len = entry.size;
		}
	}

	/* Limit the size of the data that we read */
	read_len = *data_len;
	if (read_len > sizeof(block_buffer)) {
		read_len = sizeof(block_buffer);
	}

/* Read the block from the file */
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
	if (is_encrypted) {
		ret = efs_read_block(abs_path, 0, block_buffer, read_len);
	} else
#endif
	{
		ret = fsu_read_abs_block(abs_path, 0, block_buffer, read_len);
	}
	if (ret < 0) {
		set_error(ERROR_GENERIC);
		*data_len = 0;
		return NULL;
	}

	return block_buffer;
}

/**
 * @brief Read block handler for the content resource
 *
 * This function is only called if the above cb_read() function indicated that the
 * file being read is larger than the CoAP block size.
 *
 * @param[in] obj_inst_id Object instance ID generating the callback.
 * @param[in] res_id Resource ID generating the callback.
 * @param[in] res_inst_id Resource instance ID generating the callback
 *                        (typically 0 for non-multi instance resources).
 * @param[in] offset Index within the large resource to start the read
 * @param[in] read_len Number of bytes to read from the large resource
 * @param[in] data Pointer to buffer data should be written to
 * @param[out] data_len Actual number of bytes written to the buffer
 * @param[out] last_block Flag used during block transfer to indicate the
 *                        last block of data. This function sets this value
 *                        to true if data written is the last block
 *
 * @return Callback returns a pointer to the data buffer or NULL for failure.
 */
static void *cb_read_block(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			   size_t offset, size_t read_len, uint8_t *data, size_t *data_len,
			   bool *last_block)
{
	char abs_path[FSU_MAX_ABS_PATH_SIZE + 1];
	struct fs_dirent entry;
	int ret;
	bool is_encrypted = false;

	/* Validate the input parameters */
	if (obj_inst_id != 0 || res_id != FS_MGMT_FILE_CONTENT_ID || res_inst_id != 0) {
		return NULL;
	}
	if (read_len == 0 || data == NULL || data_len == NULL || last_block == NULL) {
		return NULL;
	}

	/* Default the data length to zero */
	*data_len = 0;

	/* Build the current path */
	(void)fsu_build_full_name(abs_path, sizeof(abs_path), CONFIG_FSU_MOUNT_POINT,
				  lwm2m_fs_mgmt_file_active_path);

	/* Get permission to read this file */
	if (permission_cb != NULL) {
		if (permission_cb(abs_path, false) == false) {
			/* Permission denied */
			set_error(ERROR_NO_PERM);
			return NULL;
		}
	}

	/* Make sure that the file exists */
	ret = fs_stat(abs_path, &entry);
	if (ret < 0) {
		set_error(ERROR_GENERIC);
		return NULL;
	} else if (entry.type == FS_DIR_ENTRY_DIR) {
		set_error(ERROR_GENERIC);
		return NULL;
	}

	/* Read the block from the file */
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
	is_encrypted = efs_is_encrypted_path(abs_path);
	if (is_encrypted) {
		ret = efs_read_block(abs_path, offset, data, read_len);
	} else
#endif
	{
		ret = fsu_read_abs_block(abs_path, offset, data, read_len);
	}
	if (ret < 0) {
		set_error(ERROR_GENERIC);
		return NULL;
	}

	/* Update the tracking variables */
	*data_len = ret;
	*last_block = false;
	if (offset + *data_len >= entry.size) {
		*last_block = true;
	}

	return data;
}

/**
 * @brief Pre-write file callback
 *
 * This function returns the pointer to our internal buffer. This buffer is used for
 * both reads and writes of files. It is returned using the pre_write callback as a
 * convenience for the engine.
 *
 * @param[in] obj_inst_id Object instance ID generating the callback.
 * @param[in] res_id Resource ID generating the callback.
 * @param[in] res_inst_id Resource instance ID generating the callback
 *                        (typically 0 for non-multi instance resources).
 * @param[out] data_len Length of the data buffer returned by the function
 *
 * @returns A data pointer to be used for accessing the file (read or write)
 */
static void *cb_pre_write(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			  size_t *data_len)
{
	if (data_len != NULL) {
		*data_len = sizeof(block_buffer);
	}
	return block_buffer;
}

/**
 * @brief Handle a write to the file contents
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
static int cb_write_content(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			    uint8_t *data, uint16_t data_len, bool last_block, size_t total_size)
{
	static size_t write_offset = 0;
	char abs_path[FSU_MAX_ABS_PATH_SIZE + 1];
	struct fs_dirent entry;
	ssize_t file_size;
	bool is_encrypted = false;
	int ret;

	/* Validate the input parameters */
	if (obj_inst_id != 0 || res_id != FS_MGMT_FILE_CONTENT_ID || res_inst_id != 0) {
		return -EINVAL;
	}

	/* Build the current path */
	(void)fsu_build_full_name(abs_path, sizeof(abs_path), CONFIG_FSU_MOUNT_POINT,
				  lwm2m_fs_mgmt_file_active_path);

	/* Check to see if the file exists */
	ret = fs_stat(abs_path, &entry);

	/* Never allow writes to a directory */
	if (ret == 0 && entry.type == FS_DIR_ENTRY_DIR) {
		LOG_ERR("cb_write_content: Cannot write to a directory %s", log_strdup(abs_path));
		set_error(ERROR_NO_PERM);
		return -EISDIR;
	}

#if defined(CONFIG_FSU_ENCRYPTED_FILES)
	/* Check to see if this is an encrypted file */
	is_encrypted = efs_is_encrypted_path(abs_path);
#endif

	/* Get permission to write this file */
	if (permission_cb != NULL) {
		if (permission_cb(abs_path, true) == false) {
			/* Permission denied */
			set_error(ERROR_NO_PERM);
			return -EPERM;
		}
	}

	/* If this is the first block, make sure the file is empty */
	if (write_offset == 0) {
		if (ret == 0 && entry.size > 0) {
			ret = fs_unlink(abs_path);
			if (ret < 0) {
				set_error(ERROR_GENERIC);
				LOG_ERR("cb_write_content: Failed to unlink file %s: %d",
					log_strdup(abs_path), ret);
				return ret;
			}
		}

		/* Update the return values from fs_stat() to match what we now know */
		ret = 0;
		file_size = 0;
	} else {
		if (ret < 0) {
			set_error(ERROR_GENERIC);
			LOG_ERR("cb_write_content: Attempt to append to non-existant file %s: %d",
				log_strdup(abs_path), ret);
			return ret;
		}

		/* Writes can only happen at the end of the file */
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
		if (is_encrypted) {
			file_size = efs_get_file_size(abs_path);
		} else
#endif
		{
			file_size = entry.size;
		}
		if (write_offset != file_size) {
			set_error(ERROR_GENERIC);
			LOG_ERR("cb_write_content: Attempt to append to middle of file %s: offset %d size %d",
				log_strdup(abs_path), write_offset, file_size);
			return -EINVAL;
		}
	}

#if defined(CONFIG_FSU_ENCRYPTED_FILES)
	if (is_encrypted) {
		ret = efs_append(abs_path, (void *)data, data_len);
	} else
#endif
	{
		ret = fsu_append_abs(abs_path, (void *)data, data_len);
	}
	if (ret < 0) {
		set_error(ERROR_GENERIC);
		LOG_ERR("cb_write_content: Error appending to %s: %d", log_strdup(abs_path), ret);
		return ret;
	}
	if (ret != data_len) {
		set_error(ERROR_GENERIC);
		LOG_ERR("cb_write_content: Error appending to %s: length mismatch %d != %d",
			log_strdup(abs_path), ret, data_len);
		return -ENOSPC;
	}

	/* Update write pointer into file */
	if (last_block) {
		write_offset = 0;
	} else {
		write_offset += data_len;
	}
	return 0;
}

/**
 * @brief Execute handler for the delete resource
 *
 * @param[in] obj_inst_id Object instance ID generating the callback.
 * @param[in] args Pointer to execute arguments payload. (This can be
 *            NULL if no arguments are provided)
 * @param[in] args_len Length of argument payload in bytes.
 *
 * @return 0 on success or <0 on error.
 */
static int cb_exec_delete(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len)
{
	char abs_path[FSU_MAX_ABS_PATH_SIZE + 1];
	struct fs_dirent entry;
	int ret;

	/* Validate the input parameters */
	if (obj_inst_id != 0) {
		return -EINVAL;
	}

	/* Build the current path */
	(void)fsu_build_full_name(abs_path, sizeof(abs_path), CONFIG_FSU_MOUNT_POINT,
				  lwm2m_fs_mgmt_file_active_path);

	/* Get permission to delete this file */
	if (permission_cb != NULL) {
		if (permission_cb(abs_path, true) == false) {
			/* Permission denied */
			set_error(ERROR_NO_PERM);
			return -EPERM;
		}
	}

	/* Check to see if the file exists */
	ret = fs_stat(abs_path, &entry);

	/* If found, try to delete */
	if (ret == 0) {
		/*
		 * Try to delete the file/directory. This will typically succeed for files,
		 * but will fail for directories if the directory is not empty. This is the
		 * desired behavior.
		 */
		ret = fs_unlink(abs_path);
	} else {
		/* Path didn't exist, so pretend delete was successful */
		ret = 0;
	}

	/* Update the error status */
	if (ret == 0) {
		set_error(ERROR_OKAY);
	} else {
		set_error(ERROR_GENERIC);
	}

	return ret;
}

/**
 * @brief Execute handler for the create resource
 *
 * @param[in] obj_inst_id Object instance ID generating the callback.
 * @param[in] args Pointer to execute arguments payload. (This can be
 *            NULL if no arguments are provided)
 * @param[in] args_len Length of argument payload in bytes.
 *
 * @return 0 on success or <0 on error.
 */
static int cb_exec_create(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len)
{
	char abs_path[FSU_MAX_ABS_PATH_SIZE + 1];
	struct fs_dirent entry;
	int ret;

	/* Validate the input parameters */
	if (obj_inst_id != 0) {
		return -EINVAL;
	}

	/* Build the current path */
	(void)fsu_build_full_name(abs_path, sizeof(abs_path), CONFIG_FSU_MOUNT_POINT,
				  lwm2m_fs_mgmt_file_active_path);

	/* Get permission to create the directory */
	if (permission_cb != NULL) {
		if (permission_cb(abs_path, true) == false) {
			/* Permission denied */
			set_error(ERROR_NO_PERM);
			return -EPERM;
		}
	}
	/* Check to see if the file/directory exists */
	ret = fs_stat(abs_path, &entry);

	if (ret == 0 && entry.type == FS_DIR_ENTRY_DIR) {
		/* Success. Directory already exists. */
	} else if (ret == 0) {
		/* Fail. Cannot create a directory with same name as an existing file. */
		set_error(ERROR_GENERIC);
		return -EEXIST;
	} else {
		/* Attempt to create the directory */
		ret = fs_mkdir(abs_path);
	}

	/* Update the error status */
	if (ret == 0) {
		set_error(ERROR_OKAY);
	} else {
		set_error(ERROR_GENERIC);
	}

	return ret;
}

/**
 * @brief Execute handler for the execute resource
 *
 * @param[in] obj_inst_id Object instance ID generating the callback.
 * @param[in] args Pointer to execute arguments payload. (This can be
 *            NULL if no arguments are provided)
 * @param[in] args_len Length of argument payload in bytes.
 *
 * @return 0 on success or <0 on error.
 */
static int cb_exec_execute(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len)
{
	/*TODO when shell scripts are implemented*/
	return 0;
}

/**
 * @brief Execute handler for the reset resource
 *
 * @param[in] obj_inst_id Object instance ID generating the callback.
 * @param[in] args Pointer to execute arguments payload. (This can be
 *            NULL if no arguments are provided)
 * @param[in] args_len Length of argument payload in bytes.
 *
 * @return 0 on success or <0 on error.
 */
static int cb_exec_reset(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len)
{
	/* Reset the state and error */
	memset(lwm2m_fs_mgmt_file_status, 0, sizeof(lwm2m_fs_mgmt_file_status));
	strcpy(lwm2m_fs_mgmt_file_status, STATUS_IDLE);
	NOTIFY_OBSERVER(LWM2M_OBJECT_FS_MGMT_FILE_ID, 0, FS_MGMT_FILE_STATUS_ID);
	set_error(ERROR_OKAY);
	return 0;
}

/**
 * @brief Create the instance of the file system management directory object
 *
 * @param[in] obj_inst_id Instance to create (ignored, assumed 0)
 *
 * @returns the created object or NULL on error
 */
static struct lwm2m_engine_obj_inst *fs_mgmt_file_create(uint16_t obj_inst_id)
{
	int i = 0;
	int j = 0;

	/* Initialize our local data */
	memset(lwm2m_fs_mgmt_file_active_path, 0, sizeof(lwm2m_fs_mgmt_file_active_path));
	memset(lwm2m_fs_mgmt_file_status, 0, sizeof(lwm2m_fs_mgmt_file_status));
	strcpy(lwm2m_fs_mgmt_file_status, STATUS_IDLE);
	memset(lwm2m_fs_mgmt_file_error, 0, sizeof(lwm2m_fs_mgmt_file_error));
	strcpy(lwm2m_fs_mgmt_file_error, ERROR_OKAY);

	/* initialize instance resource data */
	init_res_instance(res_inst, ARRAY_SIZE(res_inst));
	INIT_OBJ_RES(FS_MGMT_FILE_PATH_ID, res, i, res_inst, j, 1, false, true,
		     lwm2m_fs_mgmt_file_active_path, sizeof(lwm2m_fs_mgmt_file_active_path), NULL,
		     NULL, NULL, NULL, NULL);
	INIT_OBJ_RES_BLOCK(FS_MGMT_FILE_CONTENT_ID, res, i, res_inst, j, 1, false, true,
			   (uint8_t *)NULL, 0, cb_read, cb_read_block, cb_pre_write, NULL,
			   cb_write_content, NULL);
	INIT_OBJ_RES_EXECUTE(FS_MGMT_FILE_DELETE_ID, res, i, cb_exec_delete);
	INIT_OBJ_RES_EXECUTE(FS_MGMT_FILE_CREATE_ID, res, i, cb_exec_create);
	INIT_OBJ_RES_EXECUTE(FS_MGMT_FILE_EXECUTE_ID, res, i, cb_exec_execute);
	INIT_OBJ_RES_DATA(FS_MGMT_FILE_STATUS_ID, res, i, res_inst, j, lwm2m_fs_mgmt_file_status,
			  sizeof(lwm2m_fs_mgmt_file_status));
	INIT_OBJ_RES_DATA(FS_MGMT_FILE_ERROR_ID, res, i, res_inst, j, lwm2m_fs_mgmt_file_error,
			  sizeof(lwm2m_fs_mgmt_file_error));
	INIT_OBJ_RES_EXECUTE(FS_MGMT_FILE_RESET_ID, res, i, cb_exec_reset);

	inst.resources = res;
	inst.resource_count = i;

	return &inst;
}
/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
void lcz_lwm2m_obj_fs_mgmt_register_cb(lcz_lwm2m_obj_fs_mgmt_permission_cb cb)
{
	permission_cb = cb;
}

/**************************************************************************************************/
/* SYS_INIT                                                                                       */
/**************************************************************************************************/
SYS_INIT(lwm2m_fs_mgmt_file_init, APPLICATION, CONFIG_LCZ_LWM2M_FS_MGMT_INIT_PRIORITY);
static int lwm2m_fs_mgmt_file_init(const struct device *dev)
{
	struct lwm2m_engine_obj_inst *obj_inst = NULL;
	int ret;

	/* Register the object */
	fs_mgmt_file.obj_id = LWM2M_OBJECT_FS_MGMT_FILE_ID;
	fs_mgmt_file.version_major = FS_MGMT_FILE_VERSION_MAJOR;
	fs_mgmt_file.version_minor = FS_MGMT_FILE_VERSION_MINOR;
	fs_mgmt_file.fields = fields;
	fs_mgmt_file.field_count = ARRAY_SIZE(fields);
	fs_mgmt_file.max_instance_count = 1;
	fs_mgmt_file.create_cb = fs_mgmt_file_create;
	lwm2m_register_obj(&fs_mgmt_file);

	/* Auto create the only instance */
	ret = lwm2m_create_obj_inst(LWM2M_OBJECT_FS_MGMT_FILE_ID, 0, &obj_inst);
	if (ret < 0) {
		LOG_ERR("lwm2m_fs_mgmt_file_init: Failed to create instance: %d", ret);
	}

	LOG_DBG("lwm2m_fs_mgmt_file_init: Create LWM2M fs mgmt file instance: 0");

	return ret;
}
