from sm_typing import Final

EXT_PREFIX = 'XSLocalEXT-'
CBT_BLOCK_SIZE = (64 * 1024)
CBTLOG_TAG = "cbtlog"
CBT_UTIL = "/usr/sbin/cbt-util"

VG_LOCATION: Final = "/dev"
VG_PREFIX: Final = "VG_XenStorage-"

# Ref counting for VDI's: we need a ref count for LV activation/deactivation
# on the master.
NS_PREFIX_LVM: Final = "lvm-"
