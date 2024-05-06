#include "decrypt.h"
#include "defines.h"
#include <ps4.h>

// #define DEBUG_SOCKET
// #define DEBUG_IP "192.168.1.200"
// #define DEBUG_PORT 9023

time_t prevtime;

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

  char buf[255];

  // Initialize PS4 Kernel, libc, and networking
  initKernel();
  initLibc();
  initSysUtil();

  // Load and resolve libkernel_sys library
  int libk = sceKernelLoadStartModule("libkernel_sys.sprx", 0, NULL, 0, 0, 0);
  RESOLVE(libk, sceKernelDebugOutText);

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

  prevtime = time(0);

  sprintf(buf, "kernel_base: %p\n", kernel_base);
  sceKernelDebugOutText(0, buf);
  sceKernelDebugOutText(0, "Running PS4 PUP Decrypter\n");
  printf_notification("Running PS4 PUP Decrypter");
  decrypt_pups(INPUTPATH, OUTPUTPATH);
  sceKernelDebugOutText(0, "Finished PS4 PUP Decrypter\n");
  printf_notification("Finished PS4 PUP Decrypter");

#ifdef DEBUG_SOCKET
  printf_debug("Closing socket...\n");
  SckClose(DEBUG_SOCK);
#endif

  return 0;
}
