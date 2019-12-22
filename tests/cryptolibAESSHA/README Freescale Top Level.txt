This library release contains updated files for the basic security functions of
the Cryptographic Acceleration Unit, both the ColdFire version (CAU) and the ARM
Cortex-Mx version (MMCAU). They are organized in the following directory structure
with the ColdFire Coprocessor CAU versions in the "cau" directory and subdirectories
and the ARM Cortex-Mx Memory Mapped CAU (MMCAU) versions in the "mmcau" directory:

mmcau_lib_release
|-- Freescale Software License Agreement.txt- enduser license agreement
|-- README.txt                              - this file
|-- cau
|   |-- cau_api.h                           - CAU header file
|   |-- cau_lib.a                           - library archive of optimized objects
|   |-- README.txt                          - calling conventions and CAU info
|   |-- lst
|   |   |-- aes_functions.lst               - listing for aes_functions.s
|   |   |-- des_functions.lst               - listing for des_functions.s
|   |   |-- md5_functions.lst               - listing for md5_functions.s
|   |   |-- sha1_functions.lst              - listing for sha1_functions.s
|   |   `-- sha256_functions.lst            - listing for sha256_functions.s
|   `-- src
|       |-- cau2_defines.hdr                - cau2 assembly source defines file
|       |-- aes_functions.s                 - aes functions assembly source
|       |-- des_functions.s                 - des functions assembly source
|       |-- md5_functions.s                 - md5 functions assembly source
|       |-- sha1_functions.s                - sha1 functions assembly source
|       `-- sha256_functions.s              - sha256 functions assembly source
|
`-- mmcau
    |-- README.txt                          - calling conventions and MMCAU info
    |-- asm-cm0p                            - library optimized for the ARMv6-M ISA
    |   |-- cau_api.h                       - CAU header file
    |   |-- lib_mmcau-cm0p.a                - library archive of optimized objects
    |   |-- lst
    |   |   |-- mmcau_aes_functions.lst     - listing for mmcau_aes_functions.s
    |   |   |-- mmcau_des_functions.lst     - listing for mmcau_des_functions.s
    |   |   |-- mmcau_md5_functions.lst     - listing for mmcau_md5_functions.s
    |   |   |-- mmcau_sha1_functions.lst    - listing for mmcau_sha1_functions.s
    |   |   `-- mmcau_sha256_functions.lst  - listing for mmcau_sha256_functions.s
    |   `-- src
    |       |-- cau2_defines.hdr            - cau2 assembly source defines file
    |       |-- mmcau_aes_functions.s       - mmcau aes functions assembly source
    |       |-- mmcau_des_functions.s       - mmcau des functions assembly source
    |       |-- mmcau_md5_functions.s       - mmcau md5 functions assembly source
    |       |-- mmcau_sha1_functions.s      - mmcau sha1 functions assembly source
    |       `-- mmcau_sha256_functions.s    - mmcau sha256 functions assembly source
    `-- asm-cm4                             - library optimized for the ARMv7-M ISA
        |-- cau_api.h                       - CAU header file
        |-- lib_mmcau.a                     - library archive of optimized objects
        |-- lst
        |   |-- mmcau_aes_functions.lst     - listing for mmcau_aes_functions.s
        |   |-- mmcau_des_functions.lst     - listing for mmcau_des_functions.s
        |   |-- mmcau_md5_functions.lst     - listing for mmcau_md5_functions.s
        |   |-- mmcau_sha1_functions.lst    - listing for mmcau_sha1_functions.s
        |   `-- mmcau_sha256_functions.lst  - listing for mmcau_sha256_functions.s
        `-- src
            |-- cau2_defines.hdr            - cau2 assembly source defines file
            |-- mmcau_aes_functions.s       - mmcau aes functions assembly source
            |-- mmcau_des_functions.s       - mmcau des functions assembly source
            |-- mmcau_md5_functions.s       - mmcau md5 functions assembly source
            |-- mmcau_sha1_functions.s      - mmcau sha1 functions assembly source
            `-- mmcau_sha256_functions.s    - mmcau sha256 functions assembly source
