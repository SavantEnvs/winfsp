/*
 * mayhem/shim/include/windows.h -- a minimal, Linux-hosted stand-in for the Windows SDK headers.
 *
 * WinFsp builds only with Visual Studio + the WDK.  The fuzz harnesses compile a handful of
 * upstream user-mode DLL sources (src/dll/fuse/fuse_opt.c, src/dll/fsop.c, src/dll/dirbuf.c,
 * src/dll/path.c, src/shared/ku/posix.c) UNMODIFIED on Linux, with this directory first on the
 * include path.  It provides only the Windows types, constants and declarations those sources and
 * the public headers (inc/winfsp/winfsp.h, fsctl.h, launch.h) need; the few Win32 functions the
 * fuzzed code really calls are implemented in mayhem/shim/win32.c.  Everything is built with
 * -fshort-wchar (WCHAR is 16-bit, as on Windows) and LONG/ULONG/DWORD are 32-bit (LLP64).
 *
 * Do NOT include libc's <string.h>/<stdlib.h> here: src/shared/um/minimal.h defines its own
 * memset/memcpy/memmove on top of RtlFillMemory/RtlMoveMemory.
 */
#ifndef MAYHEM_SHIM_WINDOWS_H
#define MAYHEM_SHIM_WINDOWS_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>     /* static_assert (C11) for FSP_FSCTL_STATIC_ASSERT */

#ifdef __cplusplus
extern "C" {
#endif

/* calling conventions / attributes */
#define WINAPI
#define NTAPI
#define APIENTRY
#define CALLBACK
#define WINADVAPI
#define NTSYSAPI
#define CONST const
#define __forceinline inline __attribute__((always_inline))
#define FORCEINLINE __forceinline
#define MEMORY_ALLOCATION_ALIGNMENT 16
/* fsctl.h declares the MSVC interlocked intrinsics with MSVC's 32-bit `long`; route them to
 * plain functions in win32.c so they do not clash with clang's -fms-extensions builtins. */
#define _InterlockedExchange mayhem_InterlockedExchange
#define _InterlockedExchangePointer mayhem_InterlockedExchangePointer
#define _ReadWriteBarrier mayhem_ReadWriteBarrier
#define UNREFERENCED_PARAMETER(P) ((void)(P))

/* basic types (LLP64) */
typedef void VOID, *PVOID, *LPVOID;
typedef const void *LPCVOID;
typedef char CHAR, *PCHAR, *PSTR, *LPSTR;
typedef const char *PCSTR, *LPCSTR, *LPCCH, *PCCH;
typedef unsigned char UCHAR, *PUCHAR, BYTE, *PBYTE, *LPBYTE, BOOLEAN, *PBOOLEAN;
typedef short SHORT, *PSHORT;
typedef unsigned short USHORT, *PUSHORT, WORD, *PWORD;
typedef int INT, *PINT, BOOL, *PBOOL, *LPBOOL, LONG, *PLONG;
typedef unsigned int UINT, *PUINT, ULONG, *PULONG, DWORD, *PDWORD, *LPDWORD;
typedef long long LONGLONG, *PLONGLONG, LONG64, *PLONG64;
typedef unsigned long long ULONGLONG, *PULONGLONG, ULONG64, *PULONG64, DWORD64;
typedef intptr_t __int3264;   /* MIDL's pointer-sized int */
typedef int8_t INT8, *PINT8;
typedef int16_t INT16, *PINT16;
typedef int32_t INT32, *PINT32;
typedef int64_t INT64, *PINT64;
typedef uint8_t UINT8, *PUINT8;
typedef uint16_t UINT16, *PUINT16;
typedef uint32_t UINT32, *PUINT32;
typedef uint64_t UINT64, *PUINT64;
typedef intptr_t INT_PTR, LONG_PTR, SSIZE_T;
typedef uintptr_t UINT_PTR, ULONG_PTR, DWORD_PTR, *PULONG_PTR;
typedef size_t SIZE_T, *PSIZE_T;
typedef wchar_t WCHAR, *PWCHAR, *PWCH, *PWSTR, *LPWSTR, *NWPSTR;
typedef const wchar_t *PCWSTR, *LPCWSTR, *LPCWCH, *PCWCH;
typedef LONG NTSTATUS, *PNTSTATUS, HRESULT;
typedef LONG LSTATUS;
typedef DWORD ACCESS_MASK, *PACCESS_MASK;
typedef DWORD SECURITY_INFORMATION, *PSECURITY_INFORMATION;
typedef WORD SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;
typedef PVOID PSECURITY_DESCRIPTOR, PSID;
typedef PVOID HANDLE, *PHANDLE, *LPHANDLE;
typedef HANDLE HMODULE, HINSTANCE, HKEY, *PHKEY, HWND, HLOCAL, SC_HANDLE;
typedef HANDLE SERVICE_STATUS_HANDLE;
typedef LONG (WINAPI *FARPROC)(void);
typedef DWORD LCID;

#define TRUE  1
#define FALSE 0
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#define FIELD_OFFSET(type, field) ((LONG)offsetof(type, field))
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))
#define MAKELANGID(p, s) ((((WORD)(s)) << 10) | (WORD)(p))
#define LOWORD(l) ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#define HIWORD(l) ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#define MAXUINT32 ((UINT32)~((UINT32)0))
#define MAXULONG 0xffffffffU

typedef struct _GUID { ULONG Data1; USHORT Data2; USHORT Data3; UCHAR Data4[8]; } GUID, *PGUID, UUID;
typedef union _LARGE_INTEGER { struct { DWORD LowPart; LONG HighPart; }; LONGLONG QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;
typedef union _ULARGE_INTEGER { struct { DWORD LowPart; DWORD HighPart; }; ULONGLONG QuadPart; } ULARGE_INTEGER, *PULARGE_INTEGER;
typedef struct _FILETIME { DWORD dwLowDateTime; DWORD dwHighDateTime; } FILETIME, *PFILETIME, *LPFILETIME;
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef struct _IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef struct _GENERIC_MAPPING { ACCESS_MASK GenericRead, GenericWrite, GenericExecute, GenericAll; } GENERIC_MAPPING, *PGENERIC_MAPPING;
typedef struct _SECURITY_ATTRIBUTES { DWORD nLength; LPVOID lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
typedef struct _SERVICE_STATUS { DWORD dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint; } SERVICE_STATUS, *LPSERVICE_STATUS;
typedef struct _RTL_SRWLOCK { PVOID Ptr; } SRWLOCK, *PSRWLOCK;
#define SRWLOCK_INIT { 0 }
typedef struct _RTL_CRITICAL_SECTION { PVOID DebugInfo; LONG LockCount; LONG RecursionCount; HANDLE OwningThread, LockSemaphore; ULONG_PTR SpinCount; } CRITICAL_SECTION, *LPCRITICAL_SECTION;
typedef union _RTL_RUN_ONCE { PVOID Ptr; } INIT_ONCE, *PINIT_ONCE, *LPINIT_ONCE;
#define INIT_ONCE_STATIC_INIT { 0 }
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef enum _TOKEN_INFORMATION_CLASS { TokenUser = 1, TokenGroups, TokenPrivileges, TokenOwner, TokenPrimaryGroup } TOKEN_INFORMATION_CLASS;
typedef BOOL (WINAPI *PINIT_ONCE_FN)(PINIT_ONCE, PVOID, PVOID *);

/* security */
typedef struct _SID_IDENTIFIER_AUTHORITY { BYTE Value[6]; } SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;
typedef struct _SID { BYTE Revision; BYTE SubAuthorityCount; SID_IDENTIFIER_AUTHORITY IdentifierAuthority; DWORD SubAuthority[1]; } SID, *PISID;
typedef struct _ACL { BYTE AclRevision; BYTE Sbz1; WORD AclSize; WORD AceCount; WORD Sbz2; } ACL, *PACL;
typedef struct _ACE_HEADER { BYTE AceType; BYTE AceFlags; WORD AceSize; } ACE_HEADER, *PACE_HEADER;
typedef struct _ACCESS_ALLOWED_ACE { ACE_HEADER Header; ACCESS_MASK Mask; DWORD SidStart; } ACCESS_ALLOWED_ACE, *PACCESS_ALLOWED_ACE;
typedef struct _ACCESS_DENIED_ACE { ACE_HEADER Header; ACCESS_MASK Mask; DWORD SidStart; } ACCESS_DENIED_ACE, *PACCESS_DENIED_ACE;
typedef struct _ACL_SIZE_INFORMATION { DWORD AceCount, AclBytesInUse, AclBytesFree; } ACL_SIZE_INFORMATION, *PACL_SIZE_INFORMATION;
typedef enum _ACL_INFORMATION_CLASS { AclRevisionInformation = 1, AclSizeInformation } ACL_INFORMATION_CLASS;
typedef struct _SECURITY_DESCRIPTOR { BYTE Revision; BYTE Sbz1; SECURITY_DESCRIPTOR_CONTROL Control; PSID Owner, Group; PACL Sacl, Dacl; } SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;
typedef enum _SID_NAME_USE { SidTypeUser = 1, SidTypeGroup, SidTypeDomain, SidTypeAlias, SidTypeWellKnownGroup, SidTypeDeletedAccount, SidTypeInvalid, SidTypeUnknown, SidTypeComputer, SidTypeLabel, SidTypeLogonSession } SID_NAME_USE, *PSID_NAME_USE;
typedef enum { WinNullSid = 0, WinWorldSid = 1, WinLocalSystemSid = 22, WinBuiltinAdministratorsSid = 26, WinAuthenticatedUserSid = 17, WinLocalServiceSid = 23, WinNetworkServiceSid = 24 } WELL_KNOWN_SID_TYPE;
#define SECURITY_DESCRIPTOR_REVISION 1
#define ACL_REVISION 2
#define ACCESS_ALLOWED_ACE_TYPE 0x0
#define ACCESS_DENIED_ACE_TYPE 0x1
#define OBJECT_INHERIT_ACE 0x1
#define CONTAINER_INHERIT_ACE 0x2
#define INHERIT_ONLY_ACE 0x8
#define INHERITED_ACE 0x10
#define SE_DACL_PRESENT 0x0004
#define SE_DACL_PROTECTED 0x1000
#define SE_DACL_AUTO_INHERITED 0x0400
#define SE_SELF_RELATIVE 0x8000
#define OWNER_SECURITY_INFORMATION 0x1
#define GROUP_SECURITY_INFORMATION 0x2
#define DACL_SECURITY_INFORMATION 0x4
#define SACL_SECURITY_INFORMATION 0x8
#define SECURITY_MAX_SID_SIZE 68
#define SECURITY_NT_AUTHORITY {0,0,0,0,0,5}
#define SECURITY_WORLD_SID_AUTHORITY {0,0,0,0,0,1}
#define SECURITY_NULL_SID_AUTHORITY {0,0,0,0,0,0}
#define SECURITY_LOCAL_SID_AUTHORITY {0,0,0,0,0,2}
#define SECURITY_CREATOR_SID_AUTHORITY {0,0,0,0,0,3}
#define SECURITY_MANDATORY_LABEL_AUTHORITY {0,0,0,0,0,16}

#define SID_REVISION 1
#define SECURITY_MAX_SID_STRING_CHARACTERS 187

/* LSA / DsGetDc types (src/shared/ku/posix.c FspPosixInitialize; not reached by the harnesses) */
typedef PVOID LSA_HANDLE, *PLSA_HANDLE;
typedef struct _LSA_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef struct _LSA_OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PLSA_UNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;
typedef enum _POLICY_INFORMATION_CLASS { PolicyAccountDomainInformation = 5, PolicyDnsDomainInformation = 12 } POLICY_INFORMATION_CLASS;
typedef struct _POLICY_ACCOUNT_DOMAIN_INFO { LSA_UNICODE_STRING DomainName; PSID DomainSid; } POLICY_ACCOUNT_DOMAIN_INFO, *PPOLICY_ACCOUNT_DOMAIN_INFO;
typedef struct _POLICY_DNS_DOMAIN_INFO { LSA_UNICODE_STRING Name, DnsDomainName, DnsForestName; GUID DomainGuid; PSID Sid; } POLICY_DNS_DOMAIN_INFO, *PPOLICY_DNS_DOMAIN_INFO;
typedef struct _DS_DOMAIN_TRUSTSW { LPWSTR NetbiosDomainName; LPWSTR DnsDomainName; ULONG Flags; ULONG ParentIndex; ULONG TrustType; ULONG TrustAttributes; PSID DomainSid; GUID DomainGuid; } DS_DOMAIN_TRUSTSW, *PDS_DOMAIN_TRUSTSW;
#define POLICY_VIEW_LOCAL_INFORMATION 0x00000001L
#define DS_DOMAIN_IN_FOREST 0x0001
#define DS_DOMAIN_DIRECT_OUTBOUND 0x0002
#define DS_DOMAIN_DIRECT_INBOUND 0x0020

/* access rights */
#define DELETE 0x00010000
#define READ_CONTROL 0x00020000
#define WRITE_DAC 0x00040000
#define WRITE_OWNER 0x00080000
#define SYNCHRONIZE 0x00100000
#define STANDARD_RIGHTS_REQUIRED 0x000F0000
#define STANDARD_RIGHTS_READ READ_CONTROL
#define STANDARD_RIGHTS_WRITE READ_CONTROL
#define STANDARD_RIGHTS_EXECUTE READ_CONTROL
#define STANDARD_RIGHTS_ALL 0x001F0000
#define ACCESS_SYSTEM_SECURITY 0x01000000
#define MAXIMUM_ALLOWED 0x02000000
#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define GENERIC_EXECUTE 0x20000000
#define GENERIC_ALL 0x10000000
#define FILE_READ_DATA 0x0001
#define FILE_LIST_DIRECTORY 0x0001
#define FILE_WRITE_DATA 0x0002
#define FILE_ADD_FILE 0x0002
#define FILE_APPEND_DATA 0x0004
#define FILE_ADD_SUBDIRECTORY 0x0004
#define FILE_READ_EA 0x0008
#define FILE_WRITE_EA 0x0010
#define FILE_EXECUTE 0x0020
#define FILE_TRAVERSE 0x0020
#define FILE_DELETE_CHILD 0x0040
#define FILE_READ_ATTRIBUTES 0x0080
#define FILE_WRITE_ATTRIBUTES 0x0100
#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)
#define FILE_GENERIC_READ (STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE)
#define FILE_GENERIC_WRITE (STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE)
#define FILE_GENERIC_EXECUTE (STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE)
#define FILE_SHARE_READ 0x1
#define FILE_SHARE_WRITE 0x2
#define FILE_SHARE_DELETE 0x4
#define FILE_ATTRIBUTE_READONLY 0x1
#define FILE_ATTRIBUTE_HIDDEN 0x2
#define FILE_ATTRIBUTE_SYSTEM 0x4
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_ARCHIVE 0x20
#define FILE_ATTRIBUTE_NORMAL 0x80
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define FILE_SUPERSEDE 0
#define FILE_OPEN 1
#define FILE_CREATE 2
#define FILE_OPEN_IF 3
#define FILE_OVERWRITE 4
#define FILE_OVERWRITE_IF 5
#define FILE_DIRECTORY_FILE 0x1
#define FILE_NON_DIRECTORY_FILE 0x40
#define FILE_DELETE_ON_CLOSE 0x1000
#define FILE_OPEN_REPARSE_POINT 0x200000
#define FILE_SUPERSEDED 0
#define FILE_OPENED 1
#define FILE_CREATED 2
#define FILE_OVERWRITTEN 3
#define FILE_EXISTS 4
#define FILE_DOES_NOT_EXIST 5

/* reparse points */
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003L
#define IO_REPARSE_TAG_SYMLINK 0xA000000CL
#define IsReparseTagMicrosoft(_tag) ((_tag) & 0x80000000)
typedef struct _REPARSE_GUID_DATA_BUFFER {
    DWORD ReparseTag; WORD ReparseDataLength; WORD Reserved; GUID ReparseGuid;
    struct { BYTE DataBuffer[1]; } GenericReparseBuffer;
} REPARSE_GUID_DATA_BUFFER, *PREPARSE_GUID_DATA_BUFFER;
#define REPARSE_GUID_DATA_BUFFER_HEADER_SIZE FIELD_OFFSET(REPARSE_GUID_DATA_BUFFER, GenericReparseBuffer)

/* nameless unions/structs (MSVC/C11) */
#define DUMMYUNIONNAME
#define DUMMYUNIONNAME2
#define DUMMYSTRUCTNAME

/* devioctl */
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define METHOD_BUFFERED 0
#define METHOD_IN_DIRECT 1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER 3
#define FILE_ANY_ACCESS 0
#define FILE_DEVICE_FILE_SYSTEM 0x00000009
#define FSCTL_SET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_GET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FILE_SPECIAL_ACCESS FILE_ANY_ACCESS

/* registry / services (declarations only) */
#define HKEY_LOCAL_MACHINE ((HKEY)(ULONG_PTR)((LONG)0x80000002))
#define KEY_WOW64_32KEY 0x0200
#define KEY_READ 0x20019
#define RRF_RT_REG_SZ 0x00000002
#define RRF_RT_REG_DWORD 0x00000010
#define SERVICE_QUERY_STATUS 0x0004
#define SERVICE_START 0x0010
#define SERVICE_STOP 0x0020
#define ERROR_SUCCESS 0L
#define ERROR_ACCESS_DENIED 5L
#define ERROR_NOT_ENOUGH_MEMORY 8L
#define ERROR_INVALID_PARAMETER 87L
#define ERROR_INSUFFICIENT_BUFFER 122L
#define ERROR_NO_UNICODE_TRANSLATION 1113L
#define ERROR_NONE_MAPPED 1332L
#define CP_UTF8 65001
#define CP_ACP 0
#define MB_ERR_INVALID_CHARS 0x8

/* Win32 functions the compiled WinFsp sources reference (mayhem/shim/win32.c) */
#define InterlockedCompareExchange(D, X, C) __sync_val_compare_and_swap((D), (C), (X))
HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName);
LPVOID WINAPI TlsGetValue(DWORD dwTlsIndex);
DWORD WINAPI GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR pSecurityDescriptor);
FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HANDLE WINAPI GetProcessHeap(void);
LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
LPVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
int WINAPI lstrlenA(LPCSTR lpString);
int WINAPI lstrlenW(LPCWSTR lpString);
DWORD WINAPI GetLastError(void);
VOID WINAPI SetLastError(DWORD dwErrCode);
int WINAPI MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,
    LPWSTR lpWideCharStr, int cchWideChar);
int WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
VOID WINAPI InitializeSRWLock(PSRWLOCK SRWLock);
VOID WINAPI AcquireSRWLockExclusive(PSRWLOCK SRWLock);
VOID WINAPI ReleaseSRWLockExclusive(PSRWLOCK SRWLock);
VOID WINAPI AcquireSRWLockShared(PSRWLOCK SRWLock);
VOID WINAPI ReleaseSRWLockShared(PSRWLOCK SRWLock);
BOOL WINAPI InitOnceExecuteOnce(PINIT_ONCE InitOnce, PINIT_ONCE_FN InitFn, PVOID Parameter, LPVOID *Context);

/* Win32 security/LSA/registry APIs referenced by src/shared/ku/posix.c and tst/winfsp-tests/posix-test.c.
 * The harnesses and the tests run by mayhem/test.sh never reach them; mayhem/shim/unreachable.c
 * defines each one to abort(). */
#define SDDL_REVISION_1 1
#define TOKEN_QUERY 0x0008
typedef struct _SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; } SID_AND_ATTRIBUTES;
typedef struct _TOKEN_USER { SID_AND_ATTRIBUTES User; } TOKEN_USER, *PTOKEN_USER;
typedef struct _TOKEN_PRIMARY_GROUP { PSID PrimaryGroup; } TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;
BOOL WINAPI AddAccessAllowedAce(PACL pAcl, DWORD dwAceRevision, DWORD AccessMask, PSID pSid);
BOOL WINAPI AddAccessDeniedAce(PACL pAcl, DWORD dwAceRevision, DWORD AccessMask, PSID pSid);
BOOL WINAPI CloseHandle(HANDLE hObject);
BOOL WINAPI ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR SecurityDescriptor, DWORD RequestedStringSDRevision, SECURITY_INFORMATION SecurityInformation, LPWSTR *StringSecurityDescriptor, PULONG StringSecurityDescriptorLen);
BOOL WINAPI ConvertSidToStringSidW(PSID Sid, LPWSTR *StringSid);
BOOL WINAPI ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision, PSECURITY_DESCRIPTOR *SecurityDescriptor, PULONG SecurityDescriptorSize);
BOOL WINAPI ConvertStringSidToSidW(LPCWSTR StringSid, PSID *Sid);
DWORD WINAPI DsEnumerateDomainTrustsW(LPWSTR ServerName, ULONG Flags, PDS_DOMAIN_TRUSTSW *Domains, PULONG DomainCount);
BOOL WINAPI EqualSid(PSID pSid1, PSID pSid2);
BOOL WINAPI GetAce(PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);
BOOL WINAPI GetAclInformation(PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);
HANDLE WINAPI GetCurrentProcess(void);
DWORD WINAPI GetLengthSid(PSID pSid);
BOOL WINAPI GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);
BOOL WINAPI GetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID *pGroup, LPBOOL lpbGroupDefaulted);
BOOL WINAPI GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID *pOwner, LPBOOL lpbOwnerDefaulted);
PSID_IDENTIFIER_AUTHORITY WINAPI GetSidIdentifierAuthority(PSID pSid);
PDWORD WINAPI GetSidSubAuthority(PSID pSid, DWORD nSubAuthority);
PUCHAR WINAPI GetSidSubAuthorityCount(PSID pSid);
BOOL WINAPI GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
BOOL WINAPI InitializeAcl(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision);
BOOL WINAPI InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
BOOL WINAPI InitializeSid(PSID Sid, PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount);
BOOL WINAPI IsValidSid(PSID pSid);
HLOCAL WINAPI LocalFree(HLOCAL hMem);
NTSTATUS NTAPI LsaClose(LSA_HANDLE ObjectHandle);
NTSTATUS NTAPI LsaFreeMemory(PVOID Buffer);
NTSTATUS NTAPI LsaOpenPolicy(PLSA_UNICODE_STRING SystemName, PLSA_OBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, PLSA_HANDLE PolicyHandle);
NTSTATUS NTAPI LsaQueryInformationPolicy(LSA_HANDLE PolicyHandle, POLICY_INFORMATION_CLASS InformationClass, PVOID *Buffer);
BOOL WINAPI MakeSelfRelativeSD(PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor, PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor, LPDWORD lpdwBufferLength);
DWORD WINAPI NetApiBufferFree(LPVOID Buffer);
BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
LSTATUS WINAPI RegGetValueW(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);
VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
BOOLEAN NTAPI RtlValidSid(PSID Sid);
BOOL WINAPI SetSecurityDescriptorControl(PSECURITY_DESCRIPTOR pSecurityDescriptor, SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest, SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet);
BOOL WINAPI SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted);
BOOL WINAPI SetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID pGroup, BOOL bGroupDefaulted);
BOOL WINAPI SetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID pOwner, BOOL bOwnerDefaulted);
#define RtlCopyMemory(D, S, L) memcpy((D), (S), (L))
#define RtlZeroMemory(D, L) memset((D), 0, (L))

/* types/declarations needed only by the prototypes in tst/winfsp-tests/winfsp-tests.h, which the
 * upstream unit tests built for mayhem/test.sh include (none of these functions is called) */
typedef struct _LUID { DWORD LowPart; LONG HighPart; } LUID, *PLUID;
typedef struct _WIN32_FIND_DATAW WIN32_FIND_DATAW, *LPWIN32_FIND_DATAW;
typedef struct _STARTUPINFOW STARTUPINFOW, *LPSTARTUPINFOW;
typedef struct _PROCESS_INFORMATION PROCESS_INFORMATION, *LPPROCESS_INFORMATION;
typedef enum _STREAM_INFO_LEVELS { FindStreamInfoStandard, FindStreamInfoMaxInfoLevel } STREAM_INFO_LEVELS;
BOOL WINAPI RemoveDirectoryW(LPCWSTR lpPathName);
BOOL WINAPI SetCurrentDirectoryW(LPCWSTR lpPathName);
BOOLEAN WINAPI CreateSymbolicLinkW(LPCWSTR lpSymlinkFileName, LPCWSTR lpTargetFileName, DWORD dwFlags);

#ifdef __cplusplus
}
#endif

#endif
