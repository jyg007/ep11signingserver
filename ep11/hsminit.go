package ep11

/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define XCPTGTMASK_SET_DOM(mask, domain)       ((mask)[((domain)/8)] |=   (1 << (7-(domain)%8)))
#include <ep11.h>
*/
import "C"
import "fmt"
import "log"
import "os"
import "encoding/hex"

// Equivalent function for XCPTGTMASK_SET_DOM
func XCPTGTMASK_SET_DOM(mask *[32]C.uchar, domain int) {
    mask[domain / 8 ] |= (1 << (7 - (domain % 8)))
}

type Target_t = C.target_t

func HsmInit(adapter uint, domain int) C.target_t {
    rc := C.m_init()
    if rc != C.XCP_OK {
            log.Fatalf("ep11 init error")
	    return 0
    }
    var target  C.target_t  = C.XCP_TGT_INIT
    var module C.struct_XCP_Module
    module.version=C.XCP_MOD_VERSION

    module.module_nr = C.uint(adapter)

    for i := range module.domainmask {
      module.domainmask[i] = 0
    }
    XCPTGTMASK_SET_DOM(&module.domainmask, domain)
    //    module.flags |= C.XCP_MFL_MODULE | C.XCP_MFL_PROBE
    module.flags |= C.XCP_MFL_VIRTUAL | C.XCP_MFL_PROBE | C.XCP_MFL_MODULE
    rc = C.m_add_module(&module, &target)
//    fmt.Printf("Module Initialiation Return Code: %d\n",rc)

     hexString := os.Getenv("EP11LOGIN")
	if hexString != "" {
	

	// Decode hex string to bytes
	blob, err := hex.DecodeString(hexString)
	if err != nil {
		fmt.Println("Failed to decode ep11 login blob string:", err)
		return 0
	}

	// Call SetLoginBlob with the decoded value
	SetLoginBlob(blob)
}
    return target
}
