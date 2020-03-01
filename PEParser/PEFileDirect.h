#pragma once
#include"windows.h"
#include"winnt.h"
#include<string>
#include<sstream>
#include<map>
#include<ctime>
#include<iomanip>
// DataDirectory
struct PEFileDirect
{
	void* FileContent;
	PIMAGE_DOS_HEADER GetImageDosHeader() {
		return (PIMAGE_DOS_HEADER)FileContent;
	}
	ULONG GetSignature() {
		return *(ULONG*)((BYTE*)FileContent + GetImageDosHeader()->e_lfanew);
	}
	PIMAGE_FILE_HEADER GetImageFileHeader() {
		PIMAGE_DOS_HEADER DosHeader = GetImageDosHeader();
		return (PIMAGE_FILE_HEADER)((BYTE*)FileContent + DosHeader->e_lfanew + sizeof(ULONG));
	}
	WORD GetSizeOfOptionalHeader() {
		auto ImageFileHeader = *GetImageFileHeader();
		return ImageFileHeader.SizeOfOptionalHeader;
	}
	bool HasImageOptionalHeader() {
		auto ImageFileHeader = *GetImageFileHeader();
		return ImageFileHeader.SizeOfOptionalHeader > 0;
	}
	PIMAGE_OPTIONAL_HEADER32 GetImageOptionalHeader32() {
		return (PIMAGE_OPTIONAL_HEADER32)((BYTE*)GetImageFileHeader() + sizeof(IMAGE_FILE_HEADER));
	}
	PIMAGE_OPTIONAL_HEADER64 GetImageOptionalHeader64() {
		return (PIMAGE_OPTIONAL_HEADER64)((BYTE*)GetImageFileHeader() + sizeof(IMAGE_FILE_HEADER));
	}
	WORD GetOptionalHeaderMagic() {
		return *(WORD*)((BYTE*)GetImageFileHeader() + sizeof(IMAGE_FILE_HEADER));
	}
	bool IsPE32() {
		return GetOptionalHeaderMagic() == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	}
	bool IsPE32Plus() {
		return GetOptionalHeaderMagic() == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	}
	std::string GetImageDosHeaderAsString() {
		auto ImageDosHeader = *GetImageDosHeader();
		const char* Format = "Magic Number: [0x%hx, %c%c]\n"
			"Bytes on last page of file: [%hu] Bytes\n"
			"Pages in file: [%hu] pages\n"
			"Relocations: [%hu]\n"
			"Size of header in paragraphs: [%hu]\n"
			"Initial (relative) SS value: [%hu]\n"
			"Initial SP value: [%hu]\n"
			"Initial IP value: [%hu]\n"
			"Initial (relative) CS value: [%hu]\n"
			"File address of relocation table: [0x%hx]\n"
			"File address of new exe header: [0x%lx]\n";
		char Buffer[4096] = {};
		sprintf(Buffer, Format,
			ImageDosHeader.e_magic, (char)ImageDosHeader.e_magic, (char)(ImageDosHeader.e_magic >> 8),
			ImageDosHeader.e_cblp,
			ImageDosHeader.e_cp,
			ImageDosHeader.e_crlc,
			ImageDosHeader.e_cparhdr,
			ImageDosHeader.e_ss,
			ImageDosHeader.e_sp,
			ImageDosHeader.e_ip,
			ImageDosHeader.e_cs,
			ImageDosHeader.e_lfarlc,
			ImageDosHeader.e_lfanew
		);
		return std::string(Buffer);
	}
	std::string GetSignatureAsString() {
		auto Signature = GetSignature();
		const char* Format = "Signature: [0x%lx, %c%c]\n";
		char Buffer[32];
		sprintf(Buffer, Format, Signature, (char)Signature, (char)(Signature >> 8), (char)(Signature >> 16), (char)(Signature >> 24));
		return std::string(Buffer);
	}
	const char* GetMachineTypeAsString() {
		auto ImageFileHeader = *GetImageFileHeader();
		static std::map<WORD, const char*> TypeMap = {
			{ IMAGE_FILE_MACHINE_UNKNOWN, "The contents of this field are assumed to be applicable to any machine type" },
			{ IMAGE_FILE_MACHINE_AM33, "Matsushita AM33" },
			{ IMAGE_FILE_MACHINE_AMD64, "x64" },
			{ IMAGE_FILE_MACHINE_ARM, "ARM little endian" },
			{ IMAGE_FILE_MACHINE_ARM64, "ARM64 little endian" },
			{ IMAGE_FILE_MACHINE_ARMNT, "ARM Thumb-2 little endian" },
			{ IMAGE_FILE_MACHINE_EBC, "EFI byte code" },
			{ IMAGE_FILE_MACHINE_I386, "Intel 386 or later processors and compatible processors" },
			{ IMAGE_FILE_MACHINE_IA64, "Intel Itanium processor family" },
			{ IMAGE_FILE_MACHINE_M32R, "Mitsubishi M32R little endian" },
			{ IMAGE_FILE_MACHINE_MIPS16, "MIPS16" },
			{ IMAGE_FILE_MACHINE_MIPSFPU, "MIPS with FPU" },
			{ IMAGE_FILE_MACHINE_MIPSFPU16, "MIPS16 with FPU" },
			{ IMAGE_FILE_MACHINE_POWERPC, "Power PC little endian" },
			{ IMAGE_FILE_MACHINE_POWERPCFP, "Power PC with floating point support" },
			{ IMAGE_FILE_MACHINE_R4000, "MIPS little endian" },
			//{ IMAGE_FILE_MACHINE_RISCV32, "RISC-V 32-bit address space" },
			//{ IMAGE_FILE_MACHINE_RISCV64, "RISC-V 64-bit address space" },
			//{ IMAGE_FILE_MACHINE_RISCV128, "RISC-V 128-bit address space" },
			{ IMAGE_FILE_MACHINE_SH3, "Hitachi SH3" },
			{ IMAGE_FILE_MACHINE_SH3DSP, "Hitachi SH3 DSP" },
			{ IMAGE_FILE_MACHINE_SH4, "Hitachi SH4" },
			{ IMAGE_FILE_MACHINE_SH5, "Hitachi SH5" },
			{ IMAGE_FILE_MACHINE_THUMB, "Thumb" },
			{ IMAGE_FILE_MACHINE_WCEMIPSV2, "MIPS little-endian WCE v2" },
		};

		auto Iter = TypeMap.find(ImageFileHeader.Machine);
		if (Iter == TypeMap.end()) {
			return "Unknown machine type.";
		}
		return (*Iter).second;
	}

	std::string GetCharacteristicsAsString() {
		auto ImageFileHeader = *GetImageFileHeader();
		static std::map<WORD, const char*> CharacteristicsMap = {
			{ IMAGE_FILE_RELOCS_STRIPPED, "Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files." },
			{ IMAGE_FILE_EXECUTABLE_IMAGE, "Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error." },
			{ IMAGE_FILE_LINE_NUMS_STRIPPED, "COFF line numbers have been removed. This flag is deprecated and should be zero." },
			{ IMAGE_FILE_LOCAL_SYMS_STRIPPED, "COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero." },
			//{ IMAGE_FILE_AGGRESSIVE_WS_TRIM, "Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero." },
			{ IMAGE_FILE_LARGE_ADDRESS_AWARE, "Application can handle > 2-GB addresses." },
			{ 0x0040, "This flag is reserved for future use." },
			{ IMAGE_FILE_BYTES_REVERSED_LO, "Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero." },
			{ IMAGE_FILE_32BIT_MACHINE, "Machine is based on a 32-bit-word architecture." },
			{ IMAGE_FILE_DEBUG_STRIPPED, "Debugging information is removed from the image file." },
			//{ IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP, "If the image is on removable media, fully load it and copy it to the swap file." },
			{ IMAGE_FILE_NET_RUN_FROM_SWAP, "If the image is on network media, fully load it and copy it to the swap file." },
			{ IMAGE_FILE_SYSTEM, "The image file is a system file, not a user program." },
			{ IMAGE_FILE_DLL, "The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run." },
			{ IMAGE_FILE_UP_SYSTEM_ONLY, "The file should be run only on a uniprocessor machine." },
			{ IMAGE_FILE_BYTES_REVERSED_HI, "Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero." },
		};
		std::stringstream Stream;
		Stream << "\n";
		auto Characteristics = ImageFileHeader.Characteristics;
		for (const auto& CharacteristicPair : CharacteristicsMap) {
			if (Characteristics & CharacteristicPair.first) {
				Stream << '\t' << CharacteristicPair.second << "\n";
			}
		}
		return Stream.str();
	}

	std::string GetTimeDateStampAsString() {
		auto ImageFileHeader = *GetImageFileHeader();
		std::time_t TimeStamp = (std::time_t)ImageFileHeader.TimeDateStamp;
		std::stringstream stream;
		stream << std::put_time(std::gmtime(&TimeStamp), "%Y-%m-%d %I:%M:%S %p");
		return stream.str();
	}

	std::string GetImageFileHeaderAsString() {
		auto ImageFileHeader = *GetImageFileHeader();
		const char* Format = "Machine: [%hu, %s]\n"
			"NumberOfSections: [%hu]\n"
			"TimeDateStamp: [%lu, %s]\n"
			"PointerToSymbolTable: [0x%lx]\n"
			"NumberOfSymbols: [%lu]\n"
			"SizeOfOptionalHeader: [%hu]\n"
			"Characteristics: [%hu, %s]\n";
		char Buffer[4096] = {};
		sprintf(Buffer, Format,
			ImageFileHeader.Machine, GetMachineTypeAsString(),
			ImageFileHeader.NumberOfSections,
			ImageFileHeader.TimeDateStamp, GetTimeDateStampAsString().c_str(),
			ImageFileHeader.PointerToSymbolTable,
			ImageFileHeader.NumberOfSymbols,
			ImageFileHeader.SizeOfOptionalHeader,
			ImageFileHeader.Characteristics, GetCharacteristicsAsString().c_str());
		return std::string(Buffer);
	}

	std::string GetDllCharacteristicsAsString() {
		auto ImageFileHeader = *GetImageFileHeader();
		static std::map<WORD, const char*> DllCharacteristicsMap = {
			{ 0x0001, "Reserved, must be zero." },
			{ 0x0002, "Reserved, must be zero." },
			{ 0x0004, "Reserved, must be zero." },
			{ 0x0008, "Reserved, must be zero." },
			{ IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "Image can handle a high entropy 64-bit virtual address space." },
			{ IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "DLL can be relocated at load time." },
			{ IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "Code Integrity checks are enforced." },
			{ IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "Image is NX compatible." },
			{ IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "Isolation aware, but do not isolate the image." },
			{ IMAGE_DLLCHARACTERISTICS_NO_SEH, "Does not use structured exception (SE) handling. No SE handler may be called in this image." },
			{ IMAGE_DLLCHARACTERISTICS_NO_BIND, "Do not bind the image." },
			{ IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "Image must execute in an AppContainer." },
			{ IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "A WDM driver." },
			{ IMAGE_DLLCHARACTERISTICS_GUARD_CF, "Image supports Control Flow Guard." },
			//{ IMAGE_DLLCHARACTERISTICS_ TERMINAL_SERVER_AWARE, "Terminal Server aware." },
		};
		std::stringstream Stream;
		Stream << "\n";
		auto Characteristics = ImageFileHeader.Characteristics;
		for (const auto& CharacteristicPair : DllCharacteristicsMap) {
			if (Characteristics & CharacteristicPair.first) {
				Stream << '\t' << CharacteristicPair.second << "\n";
			}
		}
		return Stream.str();
	}

	std::string GetSubsystemAsString(bool IsPE32Plus) {
		static std::map<WORD, const char*> SubsystemMap = {
			{ IMAGE_SUBSYSTEM_UNKNOWN, "An unknown subsystem" },
			{ IMAGE_SUBSYSTEM_NATIVE, "Device drivers and native Windows processes" },
			{ IMAGE_SUBSYSTEM_WINDOWS_GUI, "The Windows graphical user interface (GUI) subsystem" },
			{ IMAGE_SUBSYSTEM_WINDOWS_CUI, "The Windows character subsystem" },
			{ IMAGE_SUBSYSTEM_OS2_CUI, "The OS/2 character subsystem" },
			{ IMAGE_SUBSYSTEM_POSIX_CUI, "The Posix character subsystem" },
			{ IMAGE_SUBSYSTEM_NATIVE_WINDOWS, "Native Win9x driver" },
			{ IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, "Windows CE" },
			{ IMAGE_SUBSYSTEM_EFI_APPLICATION, "An Extensible Firmware Interface (EFI) application" },
			//{ IMAGE_SUBSYSTEM_EFI_BOOT_ SERVICE_DRIVER, "An EFI driver with boot services" },
			//{ IMAGE_SUBSYSTEM_EFI_RUNTIME_ DRIVER, "An EFI driver with run-time services" },
			{ IMAGE_SUBSYSTEM_EFI_ROM, "An EFI ROM image" },
			{ IMAGE_SUBSYSTEM_XBOX, "XBOX" },
			{ IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, "Windows boot application." },
		};
		WORD Subsystem = 0;
		if (IsPE32()) {
			GetImageOptionalHeader32()->Subsystem;
		}
		else {
			GetImageOptionalHeader64()->Subsystem;
		}
		auto Iter = SubsystemMap.find(Subsystem);
		if (Iter == SubsystemMap.end()) {
			return "Unknown subsystem type.";
		}
		return (*Iter).second;
	}

	std::string GetImageOptionalHeader64AsString() {
		const auto& ImageOptionalHeader64 = *GetImageOptionalHeader64();
		const char* Format = "PE Format: [%hu, %s]\n"
			"MajorLinkerVersion: [%hhu]\n"
			"MinorLinkerVersion: [%hhu]\n"
			"SizeOfCode: [%lu]\n"
			"SizeOfInitializedData: [%lu]\n"
			"SizeOfUninitializedData: [%lu]\n"
			"AddressOfEntryPoint: [0x%lx]\n"
			"BaseOfCode: [0x%lx]\n"
			"ImageBase: [0x%llx]\n"
			"SectionAlignment: [%lu]\n"
			"FileAlignment: [%lu]\n"
			"MajorOperatingSystemVersion: [%hu]\n"
			"MinorOperatingSystemVersion: [%hu]\n"
			"MajorImageVersion: [%hu]\n"
			"MinorImageVersion: [%hu]\n"
			"MajorSubsystemVersion: [%hu]\n"
			"MinorSubsystemVersion: [%hu]\n"
			"Win32VersionValue: [%lu]\n"
			"SizeOfImage: [%lu]\n"
			"SizeOfHeaders: [%lu]\n"
			"Subsystem: [%hu, %s]\n"
			"DllCharateristics: [%s]\n"
			"SizeOfStackReserve: [%llu]\n"
			"SizeOfStackCommit: [%llu]\n"
			"SizeOfHeapReserve: [%llu]\n"
			"SizeOfHeapCommit: [%llu]\n"
			"NumberOfRvaAndSizes: [%lu]\n";
		char Buffer[8192] = {};
		sprintf(Buffer, Format,
			ImageOptionalHeader64.Magic, ImageOptionalHeader64.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "PE32" :
			(ImageOptionalHeader64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE32+" : "Unkown"),
			ImageOptionalHeader64.MajorLinkerVersion,
			ImageOptionalHeader64.MinorLinkerVersion,
			ImageOptionalHeader64.SizeOfCode,
			ImageOptionalHeader64.SizeOfInitializedData,
			ImageOptionalHeader64.SizeOfUninitializedData,
			ImageOptionalHeader64.AddressOfEntryPoint,
			ImageOptionalHeader64.BaseOfCode,
			ImageOptionalHeader64.ImageBase,
			ImageOptionalHeader64.SectionAlignment,
			ImageOptionalHeader64.FileAlignment,
			ImageOptionalHeader64.MajorOperatingSystemVersion,
			ImageOptionalHeader64.MinorOperatingSystemVersion,
			ImageOptionalHeader64.MajorImageVersion,
			ImageOptionalHeader64.MinorImageVersion,
			ImageOptionalHeader64.MajorSubsystemVersion,
			ImageOptionalHeader64.MinorSubsystemVersion,
			ImageOptionalHeader64.Win32VersionValue,
			ImageOptionalHeader64.SizeOfImage,
			ImageOptionalHeader64.SizeOfHeaders,
			ImageOptionalHeader64.Subsystem, GetSubsystemAsString(false).c_str(),
			GetDllCharacteristicsAsString().c_str(),
			ImageOptionalHeader64.SizeOfStackReserve,
			ImageOptionalHeader64.SizeOfStackCommit,
			ImageOptionalHeader64.SizeOfHeapReserve,
			ImageOptionalHeader64.SizeOfHeapCommit,
			ImageOptionalHeader64.NumberOfRvaAndSizes
		);
		return std::string(Buffer);
	}

	std::string GetImageOptionalHeader32AsString() {
		const auto& ImageOptionalHeader32 = *GetImageOptionalHeader32();;
		const char* Format = "PE Format: [%hu, %s]\n"
			"MajorLinkerVersion: [%hhu]\n"
			"MinorLinkerVersion: [%hhu]\n"
			"SizeOfCode: [%lu]\n"
			"SizeOfInitializedData: [%lu]\n"
			"SizeOfUninitializedData: [%lu]\n"
			"AddressOfEntryPoint: [0x%lx]\n"
			"BaseOfCode: [0x%lx]\n"
			"BaseOfData: [0x%lx]\n"
			"ImageBase: [0x%lx]\n"
			"SectionAlignment: [%lu]\n"
			"FileAlignment: [%lu]\n"
			"MajorOperatingSystemVersion: [%hu]\n"
			"MinorOperatingSystemVersion: [%hu]\n"
			"MajorImageVersion: [%hu]\n"
			"MinorImageVersion: [%hu]\n"
			"MajorSubsystemVersion: [%hu]\n"
			"MinorSubsystemVersion: [%hu]\n"
			"Win32VersionValue: [%lu]\n"
			"SizeOfImage: [%lu]\n"
			"SizeOfHeaders: [%lu]\n"
			"Subsystem: [%hu, %s]\n"
			"DllCharateristics: [%s]\n"
			"SizeOfStackReserve: [%lu]\n"
			"SizeOfStackCommit: [%lu]\n"
			"SizeOfHeapReserve: [%lu]\n"
			"SizeOfHeapCommit: [%lu]\n"
			"NumberOfRvaAndSizes: [%lu]\n";
		char Buffer[8192] = {};
		sprintf(Buffer, Format,
			ImageOptionalHeader32.Magic, ImageOptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "PE32" :
			(ImageOptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE32+" : "Unkown"),
			ImageOptionalHeader32.MajorLinkerVersion,
			ImageOptionalHeader32.MinorLinkerVersion,
			ImageOptionalHeader32.SizeOfCode,
			ImageOptionalHeader32.SizeOfInitializedData,
			ImageOptionalHeader32.SizeOfUninitializedData,
			ImageOptionalHeader32.AddressOfEntryPoint,
			ImageOptionalHeader32.BaseOfCode,
			ImageOptionalHeader32.BaseOfData,
			ImageOptionalHeader32.ImageBase,
			ImageOptionalHeader32.SectionAlignment,
			ImageOptionalHeader32.FileAlignment,
			ImageOptionalHeader32.MajorOperatingSystemVersion,
			ImageOptionalHeader32.MinorOperatingSystemVersion,
			ImageOptionalHeader32.MajorImageVersion,
			ImageOptionalHeader32.MinorImageVersion,
			ImageOptionalHeader32.MajorSubsystemVersion,
			ImageOptionalHeader32.MinorSubsystemVersion,
			ImageOptionalHeader32.Win32VersionValue,
			ImageOptionalHeader32.SizeOfImage,
			ImageOptionalHeader32.SizeOfHeaders,
			ImageOptionalHeader32.Subsystem, GetSubsystemAsString(true).c_str(),
			GetDllCharacteristicsAsString().c_str(),
			ImageOptionalHeader32.SizeOfStackReserve,
			ImageOptionalHeader32.SizeOfStackCommit,
			ImageOptionalHeader32.SizeOfHeapReserve,
			ImageOptionalHeader32.SizeOfHeapCommit,
			ImageOptionalHeader32.NumberOfRvaAndSizes
		);
		return std::string(Buffer);
	}
};

