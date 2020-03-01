table='''96/112
8
Export Table
The export table address and size. For more information see .edata Section (Image Only).
104/120
8
Import Table
The import table address and size. For more information, see The .idata Section.
112/128
8
Resource Table
The resource table address and size. For more information, see The .rsrc Section.
120/136
8
Exception Table
The exception table address and size. For more information, see The .pdata Section.
128/144
8
Certificate Table
The attribute certificate table address and size. For more information, see The Attribute Certificate Table (Image Only).
136/152
8
Base Relocation Table
The base relocation table address and size. For more information, see The .reloc Section (Image Only).
144/160
8
Debug
The debug data starting address and size. For more information, see The .debug Section.
152/168
8
Architecture
Reserved, must be 0
160/176
8
Global Ptr
The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
168/184
8
TLS Table
The thread local storage (TLS) table address and size. For more information, The .tls Section.
176/192
8
Load Config Table
The load configuration table address and size. For more information, The Load Configuration Structure (Image Only).
184/200
8
Bound Import
The bound import table address and size.
192/208
8
IAT
The import address table address and size. For more information, see Import Address Table.
200/216
8
Delay Import Descriptor
The delay import descriptor address and size. For more information, see Delay-Load Import Tables (Image Only).
208/224
8
CLR Runtime Header
The CLR runtime header address and size. For more information, see The .cormeta Section (Object Only).
216/232
8
Reserved, must be zero
No description.
'''
output = open('Output.txt', 'w+')
output.write(' '* 8 + 'static std::map<int, const char*> DataDirectoryMap = {\n')
table_lines = table.split('\n')
i = 0
entry_count = 0
while i + 3 < len(table_lines):
    dir_name = table_lines[i+2]
    desc = table_lines[i+3]
    output.write(' ' * 12 + "{{ {}, \"{}:    {}\" }},\n".format(entry_count, dir_name, desc))
    entry_count += 1
    i += 4
output.write(' '* 8 + '};\n')
output.close()