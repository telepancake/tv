#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x994aadfe, "proc_mkdir" },
	{ 0x73369fdb, "proc_create" },
	{ 0x7c898386, "register_kretprobe" },
	{ 0xe8213e80, "_printk" },
	{ 0x1c3ccb5e, "proc_remove" },
	{ 0xbeb1d261, "destroy_workqueue" },
	{ 0x2f990486, "path_put" },
	{ 0x1418bda3, "unregister_kretprobe" },
	{ 0x40a621c5, "snprintf" },
	{ 0x2cd42066, "task_active_pid_ns" },
	{ 0x34682121, "__task_pid_nr_ns" },
	{ 0x0f3e590f, "init_pid_ns" },
	{ 0xee139a2f, "strncpy_from_user" },
	{ 0x748854ed, "const_current_task" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xa78f1ea5, "kmalloc_caches" },
	{ 0x6ec42539, "__kmalloc_cache_noprof" },
	{ 0xd710adbf, "__kmalloc_large_noprof" },
	{ 0xd7a59a65, "vmalloc_noprof" },
	{ 0x5403c125, "__init_waitqueue_head" },
	{ 0x361ef55d, "fget" },
	{ 0xc689cda3, "fput" },
	{ 0x818c60e4, "file_path" },
	{ 0x43a349ca, "strlen" },
	{ 0xde338d9a, "_raw_spin_lock" },
	{ 0x2f990486, "path_get" },
	{ 0xeb2f2059, "pv_ops" },
	{ 0xd272d446, "BUG_func" },
	{ 0xf4c3fbcd, "d_path" },
	{ 0x680628e7, "ktime_get_real_ts64" },
	{ 0x076801dd, "__tracepoint_mmap_lock_start_locking" },
	{ 0xa59da3c0, "down_read" },
	{ 0x076801dd, "__tracepoint_mmap_lock_acquire_returned" },
	{ 0x076801dd, "__tracepoint_mmap_lock_released" },
	{ 0xa59da3c0, "up_read" },
	{ 0x5585f85e, "iterate_fd" },
	{ 0x4a351220, "__mmap_lock_do_trace_released" },
	{ 0x4a155c75, "__mmap_lock_do_trace_acquire_returned" },
	{ 0x4a351220, "__mmap_lock_do_trace_start_locking" },
	{ 0x366ddfcc, "memchr" },
	{ 0x75738bed, "__warn_printk" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0xa4c0178c, "kvfree_call_rcu" },
	{ 0xe7269688, "seq_read" },
	{ 0xfce1f64c, "seq_lseek" },
	{ 0x6d8bd5c2, "single_release" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0xe1e1f979, "_raw_spin_lock_irqsave" },
	{ 0x81a1a811, "_raw_spin_unlock_irqrestore" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0x16dc1347, "get_task_mm" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x0bd2a011, "access_process_vm" },
	{ 0x3479650a, "mmput" },
	{ 0xc7eeeeb0, "single_open" },
	{ 0xf46d5bf3, "mutex_lock" },
	{ 0x16ab4215, "__wake_up" },
	{ 0xbeb1d261, "__flush_workqueue" },
	{ 0xf1de9e85, "vfree" },
	{ 0xb9fcd065, "call_rcu" },
	{ 0xf46d5bf3, "mutex_unlock" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0x1c489eb6, "register_kprobe" },
	{ 0x7a8e92c6, "unregister_kprobe" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x7851be11, "__cond_resched" },
	{ 0x546c19d9, "validate_usercopy_range" },
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0x7a5ffe84, "init_wait_entry" },
	{ 0xd272d446, "schedule" },
	{ 0x0db8d68d, "prepare_to_wait_event" },
	{ 0xc87f4bab, "finish_wait" },
	{ 0xa53f4e29, "memcpy" },
	{ 0x49733ad6, "queue_work_on" },
	{ 0x124ac38b, "seq_printf" },
	{ 0xa1863934, "kern_path" },
	{ 0xdf4bee3d, "alloc_workqueue_noprof" },
	{ 0x00bc5fb3, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x994aadfe,
	0x73369fdb,
	0x7c898386,
	0xe8213e80,
	0x1c3ccb5e,
	0xbeb1d261,
	0x2f990486,
	0x1418bda3,
	0x40a621c5,
	0x2cd42066,
	0x34682121,
	0x0f3e590f,
	0xee139a2f,
	0x748854ed,
	0xbd03ed67,
	0xa78f1ea5,
	0x6ec42539,
	0xd710adbf,
	0xd7a59a65,
	0x5403c125,
	0x361ef55d,
	0xc689cda3,
	0x818c60e4,
	0x43a349ca,
	0xde338d9a,
	0x2f990486,
	0xeb2f2059,
	0xd272d446,
	0xf4c3fbcd,
	0x680628e7,
	0x076801dd,
	0xa59da3c0,
	0x076801dd,
	0x076801dd,
	0xa59da3c0,
	0x5585f85e,
	0x4a351220,
	0x4a155c75,
	0x4a351220,
	0x366ddfcc,
	0x75738bed,
	0x092a35a2,
	0xa4c0178c,
	0xe7269688,
	0xfce1f64c,
	0x6d8bd5c2,
	0xd272d446,
	0xd272d446,
	0xcb8b6ec6,
	0xe1e1f979,
	0x81a1a811,
	0x90a48d82,
	0x16dc1347,
	0xd710adbf,
	0x0bd2a011,
	0x3479650a,
	0xc7eeeeb0,
	0xf46d5bf3,
	0x16ab4215,
	0xbeb1d261,
	0xf1de9e85,
	0xb9fcd065,
	0xf46d5bf3,
	0xbd03ed67,
	0x1c489eb6,
	0x7a8e92c6,
	0xd272d446,
	0x5a844b26,
	0xe4de56b4,
	0x7851be11,
	0x546c19d9,
	0xa61fd7aa,
	0x092a35a2,
	0x7a5ffe84,
	0xd272d446,
	0x0db8d68d,
	0xc87f4bab,
	0xa53f4e29,
	0x49733ad6,
	0x124ac38b,
	0xa1863934,
	0xdf4bee3d,
	0x00bc5fb3,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"proc_mkdir\0"
	"proc_create\0"
	"register_kretprobe\0"
	"_printk\0"
	"proc_remove\0"
	"destroy_workqueue\0"
	"path_put\0"
	"unregister_kretprobe\0"
	"snprintf\0"
	"task_active_pid_ns\0"
	"__task_pid_nr_ns\0"
	"init_pid_ns\0"
	"strncpy_from_user\0"
	"const_current_task\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"__kmalloc_large_noprof\0"
	"vmalloc_noprof\0"
	"__init_waitqueue_head\0"
	"fget\0"
	"fput\0"
	"file_path\0"
	"strlen\0"
	"_raw_spin_lock\0"
	"path_get\0"
	"pv_ops\0"
	"BUG_func\0"
	"d_path\0"
	"ktime_get_real_ts64\0"
	"__tracepoint_mmap_lock_start_locking\0"
	"down_read\0"
	"__tracepoint_mmap_lock_acquire_returned\0"
	"__tracepoint_mmap_lock_released\0"
	"up_read\0"
	"iterate_fd\0"
	"__mmap_lock_do_trace_released\0"
	"__mmap_lock_do_trace_acquire_returned\0"
	"__mmap_lock_do_trace_start_locking\0"
	"memchr\0"
	"__warn_printk\0"
	"_copy_from_user\0"
	"kvfree_call_rcu\0"
	"seq_read\0"
	"seq_lseek\0"
	"single_release\0"
	"__fentry__\0"
	"__x86_return_thunk\0"
	"kfree\0"
	"_raw_spin_lock_irqsave\0"
	"_raw_spin_unlock_irqrestore\0"
	"__ubsan_handle_out_of_bounds\0"
	"get_task_mm\0"
	"__kmalloc_noprof\0"
	"access_process_vm\0"
	"mmput\0"
	"single_open\0"
	"mutex_lock\0"
	"__wake_up\0"
	"__flush_workqueue\0"
	"vfree\0"
	"call_rcu\0"
	"mutex_unlock\0"
	"__ref_stack_chk_guard\0"
	"register_kprobe\0"
	"unregister_kprobe\0"
	"__stack_chk_fail\0"
	"__x86_indirect_thunk_rax\0"
	"__ubsan_handle_load_invalid_value\0"
	"__cond_resched\0"
	"validate_usercopy_range\0"
	"__check_object_size\0"
	"_copy_to_user\0"
	"init_wait_entry\0"
	"schedule\0"
	"prepare_to_wait_event\0"
	"finish_wait\0"
	"memcpy\0"
	"queue_work_on\0"
	"seq_printf\0"
	"kern_path\0"
	"alloc_workqueue_noprof\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "1E14EB56E21E313570BCAC7");
