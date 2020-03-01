table='''0x0001
0x0001
Reserved, must be zero.
0x0002
0x0002
Reserved, must be zero.
0x0004
0x0004
Reserved, must be zero.
0x0008
0x0008
Reserved, must be zero.
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
0x0020
Image can handle a high entropy 64-bit virtual address space.
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
0x0040
DLL can be relocated at load time.
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
0x0080
Code Integrity checks are enforced.
IMAGE_DLLCHARACTERISTICS_NX_COMPAT
0x0100
Image is NX compatible.
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
0x0200
Isolation aware, but do not isolate the image.
IMAGE_DLLCHARACTERISTICS_NO_SEH
0x0400
Does not use structured exception (SE) handling. No SE handler may be called in this image.
IMAGE_DLLCHARACTERISTICS_NO_BIND
0x0800
Do not bind the image.
IMAGE_DLLCHARACTERISTICS_APPCONTAINER
0x1000
Image must execute in an AppContainer.
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
0x2000
A WDM driver.
IMAGE_DLLCHARACTERISTICS_GUARD_CF
0x4000
Image supports Control Flow Guard.
IMAGE_DLLCHARACTERISTICS_ TERMINAL_SERVER_AWARE
0x8000
Terminal Server aware.
'''
output = open('Output.txt', 'w+')
output.write(' '* 8 + 'static std::map<WORD, const char*> DllCharacteristicsMap = {\n')
table_lines = table.split('\n')
i = 0
while i < len(table_lines) - 1:
    const_name = table_lines[i]
    str_name = table_lines[i+2]
    output.write(' ' * 12 + "{{ {}, \"{}\" }},\n".format(const_name, str_name))
    i += 3
output.write(' '* 8 + '};\n')
output.close()