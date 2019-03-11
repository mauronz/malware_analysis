#pragma once

#include <Windows.h>

//0x8 bytes (sizeof)
struct _UNICODE_STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	USHORT* Buffer;                                                         //0x4
};

//0x248 bytes (sizeof)
typedef struct _PEB
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsLegacyProcess : 1;                                        //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR SpareBits : 3;                                              //0x3
		};
	};
	VOID* Mutant;                                                           //0x4
	VOID* ImageBaseAddress;                                                 //0x8
	struct _PEB_LDR_DATA* Ldr;                                              //0xc
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
	VOID* SubSystemData;                                                    //0x14
	VOID* ProcessHeap;                                                      //0x18
	struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
	VOID* AtlThunkSListPtr;                                                 //0x20
	VOID* IFEOKey;                                                          //0x24
	union
	{
		ULONG CrossProcessFlags;                                            //0x28
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x28
			ULONG ProcessInitializing : 1;                                    //0x28
			ULONG ProcessUsingVEH : 1;                                        //0x28
			ULONG ProcessUsingVCH : 1;                                        //0x28
			ULONG ProcessUsingFTH : 1;                                        //0x28
			ULONG ReservedBits0 : 27;                                         //0x28
		};
	};
	union
	{
		VOID* KernelCallbackTable;                                          //0x2c
		VOID* UserSharedInfoPtr;                                            //0x2c
	};
	ULONG SystemReserved[1];                                                //0x30
	ULONG AtlThunkSListPtr32;                                               //0x34
	VOID* ApiSetMap;                                                        //0x38
	ULONG TlsExpansionCounter;                                              //0x3c
	VOID* TlsBitmap;                                                        //0x40
	ULONG TlsBitmapBits[2];                                                 //0x44
	VOID* ReadOnlySharedMemoryBase;                                         //0x4c
	VOID* HotpatchInformation;                                              //0x50
	VOID** ReadOnlyStaticServerData;                                        //0x54
	VOID* AnsiCodePageData;                                                 //0x58
	VOID* OemCodePageData;                                                  //0x5c
	VOID* UnicodeCaseTableData;                                             //0x60
	ULONG NumberOfProcessors;                                               //0x64
	ULONG NtGlobalFlag;                                                     //0x68
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
	ULONG HeapSegmentReserve;                                               //0x78
	ULONG HeapSegmentCommit;                                                //0x7c
	ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
	ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
	ULONG NumberOfHeaps;                                                    //0x88
	ULONG MaximumNumberOfHeaps;                                             //0x8c
	VOID** ProcessHeaps;                                                    //0x90
	VOID* GdiSharedHandleTable;                                             //0x94
	VOID* ProcessStarterHelper;                                             //0x98
	ULONG GdiDCAttributeList;                                               //0x9c
	struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0xa0
	ULONG OSMajorVersion;                                                   //0xa4
	ULONG OSMinorVersion;                                                   //0xa8
	USHORT OSBuildNumber;                                                   //0xac
	USHORT OSCSDVersion;                                                    //0xae
	ULONG OSPlatformId;                                                     //0xb0
	ULONG ImageSubsystem;                                                   //0xb4
	ULONG ImageSubsystemMajorVersion;                                       //0xb8
	ULONG ImageSubsystemMinorVersion;                                       //0xbc
	ULONG ActiveProcessAffinityMask;                                        //0xc0
	ULONG GdiHandleBuffer[34];                                              //0xc4
	VOID(*PostProcessInitRoutine)();                                       //0x14c
	VOID* TlsExpansionBitmap;                                               //0x150
	ULONG TlsExpansionBitmapBits[32];                                       //0x154
	ULONG SessionId;                                                        //0x1d4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
	VOID* pShimData;                                                        //0x1e8
	VOID* AppCompatInfo;                                                    //0x1ec
	struct _UNICODE_STRING CSDVersion;                                      //0x1f0
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x1f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x1fc
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x200
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x204
	ULONG MinimumStackCommit;                                               //0x208
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x20c
	struct _LIST_ENTRY FlsListHead;                                         //0x210
	VOID* FlsBitmap;                                                        //0x218
	ULONG FlsBitmapBits[4];                                                 //0x21c
	ULONG FlsHighIndex;                                                     //0x22c
	VOID* WerRegistrationData;                                              //0x230
	VOID* WerShipAssertPtr;                                                 //0x234
	VOID* pContextData;                                                     //0x238
	VOID* pImageHeaderHash;                                                 //0x23c
	union
	{
		ULONG TracingFlags;                                                 //0x240
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x240
			ULONG CritSecTracingEnabled : 1;                                  //0x240
			ULONG SpareTracingBits : 30;                                      //0x240
		};
	};
} PEB, *PPEB;