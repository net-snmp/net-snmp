/*
 *  Host Resources 'wrapper' interface
 *	calls the per-group interfaces from 'hr_*.h'
 */

	config_require(hr_system)
	config_require(hr_storage)
	config_require(hr_device)
	config_require(hr_other)
	config_require(hr_proc)
	config_require(hr_network)
	config_require(hr_print)
	config_require(hr_disk)
	config_require(hr_partition)
	config_require(hr_filesys)
	config_require(hr_swrun)
	config_require(hr_swinst)
	config_require(hr_utils)

