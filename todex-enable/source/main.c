#include "ps4.h"

static int( * sceKernelDebugOutText)(int,
  const char * ) = NULL;
size_t page_size = 0x4000;


void * kernel_base = NULL;

int kpayload(struct thread * td) {
  kernel_base = & ((uint8_t * ) __readmsr(0xC0000082))[-0x1C0];

  struct ucred * cred = td -> td_proc -> p_ucred;
  cred -> cr_uid = 0;
  cred -> cr_ruid = 0;
  cred -> cr_rgid = 0;
  cred -> cr_groups[0] = 0;

  // escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
  void * td_ucred = * (void ** )(((char * ) td) + 304); // p_ucred == td_ucred

  // sceSblACMgrIsSystemUcred
  uint64_t * sonyCred = (uint64_t * )(((char * ) td_ucred) + 96);
  * sonyCred = 0xffffffffffffffff;

  // sceSblACMgrGetDeviceAccessType
  uint64_t * sceProcType = (uint64_t * )(((char * ) td_ucred) + 88);
  * sceProcType = 0x3801000000000013; // Max access

  // sceSblACMgrHasSceProcessCapability
  uint64_t * sceProcCap = (uint64_t * )(((char * ) td_ucred) + 104);
  * sceProcCap = 0xffffffffffffffff; // Sce Process
 #if FIRMWARE == 505 // FW 5.05
*(unsigned char*)(kernel_base + 0x01CD068D) = 0x82;
#endif
#if ((FIRMWARE == 650) || (FIRMWARE == 651) || (FIRMWARE == 670) || (FIRMWARE == 671) || (FIRMWARE == 672))  // FW 6.50-6.72
*(unsigned char*)(kernel_base + 0x01BD800D) = 0x82;
#endif
#if ((FIRMWARE == 700) || (FIRMWARE == 701) || (FIRMWARE == 702))  // FW 7.0X
*(unsigned char*)(kernel_base + 0x022FED8D) = 0x82;
#endif
#if ((FIRMWARE == 750) || (FIRMWARE == 751) || (FIRMWARE == 755))  // FW 7.5X
*(unsigned char*)(kernel_base + 0x022287CD) = 0x82;
#endif
#if ((FIRMWARE == 800) || (FIRMWARE == 801) || (FIRMWARE == 803))  // FW 8.0X
*(unsigned char*)(kernel_base + 0x01B5158D) = 0x82;
#endif
#if ((FIRMWARE == 850) || (FIRMWARE == 852))  // FW 8.5X
*(unsigned char*)(kernel_base + 0x01C8338D) = 0x82;
#endif
#if FIRMWARE == 900  // FW 9.00
*(unsigned char*)(kernel_base + 0x0221688D) = 0x82;
#endif
#if ((FIRMWARE == 903) || (FIRMWARE == 904))  // FW 9.03 & 9.04
*(unsigned char*)(kernel_base + 0x0221288D) = 0x82;
#endif
#if ((FIRMWARE == 950) || (FIRMWARE == 951) || (FIRMWARE == 960))  // FW 9.5X-9.60
*(unsigned char*)(kernel_base + 0x0221A40D) = 0x82;
#endif
#if ((FIRMWARE == 1000) || (FIRMWARE == 1001))  // FW 10.00 & 10.01
*(unsigned char*)(kernel_base + 0x01B9E08D) = 0x82;
#endif
#if ((FIRMWARE == 1050) || (FIRMWARE == 1070) || (FIRMWARE == 1071))  // FW 10.20 & 10,70
*(unsigned char*)(kernel_base + 0x01BE460D) = 0x82;
#endif
#if ((FIRMWARE == 1100) || (FIRMWARE == 1102))  // FW 11.00 & 11.02
*(unsigned char*)(kernel_base + 0x0221C60D) = 0x82;
#endif
  //convert tid to dex
	//*(unsigned char*)(kernel_base + K1100_TARGET_ID) = 0x82;

  return 0;
}

int _main(struct thread * td) {
  UNUSED(td);
 

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
   //jailbreak();
  syscall(11, &kpayload, NULL);
  
  printf_notification("Todex Enabled");
	return 0;
}
