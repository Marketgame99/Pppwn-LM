#include <ps4.h>

// #define DEBUG_SOCKET
// #define DEBUG_IP "192.168.1.200"
// #define DEBUG_PORT 9023

static int (*sceKernelDebugOutText)(int,
                                    const char *) = NULL;
// size_t page_size = 0x4000;

void *kernel_base = NULL;
int kpayload(struct thread *td) {
  kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-0x1C0];

  struct ucred *cred = td->td_proc->p_ucred;
  cred->cr_uid = 0;
  cred->cr_ruid = 0;
  cred->cr_rgid = 0;
  cred->cr_groups[0] = 0;

  // escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
  void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

  // sceSblACMgrIsSystemUcred
  uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
  *sonyCred = 0xffffffffffffffff;

  // sceSblACMgrGetDeviceAccessType
  uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
  *sceProcType = 0x3801000000000013; // Max access

  // sceSblACMgrHasSceProcessCapability
  uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
  *sceProcCap = 0xffffffffffffffff; // Sce Process

  return 0;
}

int _main(struct thread *td) {
  UNUSED(td);

  // Initialize PS4 Kernel, libc, and networking
  initKernel();
  initLibc();
  initSysUtil();

  // Load and resolve libkernel_sys library
  int libk = sceKernelLoadStartModule("libkernel_sys.sprx", 0, NULL, 0, 0, 0);
  RESOLVE(libk, sceKernelDebugOutText);

  sceKernelSleep(1);

  // Output initialization messages
  if (sceKernelDebugOutText) {
    sceKernelDebugOutText(0, "==========================\n");
    sceKernelDebugOutText(0, "Hello From inside Shellcore!!!\n");
    sceKernelDebugOutText(0, "==========================\n");
  }

#ifdef DEBUG_SOCKET
  initNetwork();
  DEBUG_SOCK = SckConnect(DEBUG_IP, DEBUG_PORT);
#endif

  // jailbreak();
  syscall(11, &kpayload, NULL);

  printf_notification("kbase: %p, waiting 5 secs", kernel_base);
  sceKernelSleep(5);

  // sceKernelDebugOutText(0, "called enable_perm_uart()\n");
  // enable_perm_uart();

  uint64_t (*icc_nvs_write)(uint32_t block, uint32_t offset, uint32_t size, void *value);

  icc_nvs_write = (void *)(kernel_base + K1100_ICC_NVS_WRITE);

  sceKernelDebugOutText(0, "called icc_nvs_write()\n");
  char uart = 1;
  icc_nvs_write(4, 0x31F, 1, &uart);

  printf_notification("Enabled UART!");

#ifdef DEBUG_SOCKET
  printf_debug("Closing socket...\n");
  SckClose(DEBUG_SOCK);
#endif

  return 0;
}
