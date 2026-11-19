/*
 * mayhem/shim/unreachable.c -- Win32 / WinFsp-internal functions that the compiled WinFsp objects
 * (fsop.c, posix.c) and upstream's tst/winfsp-tests/posix-test.c reference, but that neither the
 * fuzz harnesses nor the unit tests run by mayhem/test.sh ever call: security descriptors, SIDs,
 * access checks, LSA/LDAP/registry lookups, process tokens, the service loop.  They exist only so
 * the objects link; each one aborts loudly if it is ever reached, so a harness that drifts onto one
 * of these paths fails instead of silently fuzzing a stub.
 */
#include <stdio.h>
#include <stdlib.h>

#define UNREACHABLE(name) \
    void name(void) { fprintf(stderr, "mayhem shim: unexpected call to %s\n", #name); abort(); }

UNREACHABLE(AddAccessAllowedAce)
UNREACHABLE(AddAccessDeniedAce)
UNREACHABLE(ConvertSecurityDescriptorToStringSecurityDescriptorW)
UNREACHABLE(ConvertSidToStringSidW)
UNREACHABLE(ConvertStringSecurityDescriptorToSecurityDescriptorW)
UNREACHABLE(ConvertStringSidToSidW)
UNREACHABLE(DsEnumerateDomainTrustsW)
UNREACHABLE(EqualSid)
UNREACHABLE(FspAccessCheckEx)
UNREACHABLE(FspCreateSecurityDescriptor)
UNREACHABLE(FspDeleteSecurityDescriptor)
UNREACHABLE(FspGetFileGenericMapping)
UNREACHABLE(FspLdapClose)
UNREACHABLE(FspLdapConnect)
UNREACHABLE(FspLdapGetDefaultNamingContext)
UNREACHABLE(FspLdapGetTrustPosixOffset)
UNREACHABLE(FspServiceStopLoop)
UNREACHABLE(GetAce)
UNREACHABLE(GetAclInformation)
UNREACHABLE(GetCurrentProcess)
UNREACHABLE(GetLengthSid)
UNREACHABLE(GetSecurityDescriptorDacl)
UNREACHABLE(GetSecurityDescriptorGroup)
UNREACHABLE(GetSecurityDescriptorLength)
UNREACHABLE(GetSecurityDescriptorOwner)
UNREACHABLE(GetSidIdentifierAuthority)
UNREACHABLE(GetSidSubAuthority)
UNREACHABLE(GetSidSubAuthorityCount)
UNREACHABLE(GetTokenInformation)
UNREACHABLE(HookCloseHandle)
UNREACHABLE(InitOnceExecuteOnce)
UNREACHABLE(InitializeAcl)
UNREACHABLE(InitializeSecurityDescriptor)
UNREACHABLE(InitializeSid)
UNREACHABLE(IsValidSid)
UNREACHABLE(LocalFree)
UNREACHABLE(LsaClose)
UNREACHABLE(LsaFreeMemory)
UNREACHABLE(LsaOpenPolicy)
UNREACHABLE(LsaQueryInformationPolicy)
UNREACHABLE(MakeSelfRelativeSD)
UNREACHABLE(NetApiBufferFree)
UNREACHABLE(OpenProcessToken)
UNREACHABLE(RegGetValueW)
UNREACHABLE(SetSecurityDescriptorControl)
UNREACHABLE(SetSecurityDescriptorDacl)
UNREACHABLE(SetSecurityDescriptorGroup)
UNREACHABLE(SetSecurityDescriptorOwner)
