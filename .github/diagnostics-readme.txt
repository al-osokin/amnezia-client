Unofficial unsigned AmneziaVPN 5.0.3.0 Windows service diagnostic build.
Base: de93650a90739b87bb47a632872ea9d0adc9412f.
This package is NOT an installer and has not been installed on the user's PC.

The service's existing synchronous DeviceIoControl calls and route API calls are
wrapped with BEGIN/END timing and numeric results. No additional driver queries,
retries, cancellation, reset policy or route logic changes are added.
Release /MD, NDEBUG and version 5.0.3.0 remain; matching PDB is included.
Qt SDK is 6.10.2 (matching the observed installed runtime); tag CI used 6.10.1.
MSVC x64 from windows-2022 and the original Conan graph are used.
Runtime/GUI/driver compatibility still requires an isolated VM test.

New numeric-only log: %ProgramData%\AmneziaVPN-service-diag-<PID>-<tick>.log.
Created lazily before the first instrumented operation, independently of UI logs.
Access is restricted to SYSTEM and Administrators. File is capped at 16 MiB per
process and truncates at the next record when full. Keep its tail after a hang.
Each process/restart has its own file; old process logs require manual cleanup.
Writes use WriteFile, not the Qt logger. OS disk cache is NOT forced per record,
so the final records may be lost in a full OS crash/power loss. The logging lock
is never held over a driver call. A sink-open failure leaves no file.
Existing application logs are unchanged and may contain private information;
only this separate diagnostic file is designed to contain no paths/IP/secrets.

Fields: tick_ms is monotonic uptime; pid/tid identify process/thread; id pairs
begin with end/exit; elapsed_ms excludes the begin record write.
IOCTL begin: a=input bytes, b=output capacity, c=control code.
IOCTL end: a=BOOL success, b=GetLastError on failure (0 on success),
c=returned bytes on success (0 on failure). Caller-visible last error is preserved.
Route API end: a=direct API return/error code (not GetLastError).
Scope 'exit' means control left the C++ scope, not that the operation succeeded.
split.state value: a=state, b=returned bytes. It uses an already-completed query.
routes.addExclusion/deleteExclusion begin: a=null address, b=protocol enum,
c=original prefix length. Unsigned fields render negative sentinel values modulo 2^64.
Other scope counts/indices are described at the instrumented call sites.

Do not run this EXE with --help/--version: the upstream main treats arguments as
console/service startup. Do not run it in parallel with the installed service.
Replacing it requires a separate approved maintenance window, backup and rollback,
stopped GUI/main service/tunnel processes, and preservation of all DLL/SYS/INF/CAT.
Never copy a whole build directory into Program Files or disable driver signing.
If the existing service cannot stop, do not replace a live EXE; reboot/rollback
must be planned locally. User-mode logs cannot prove a specific kernel deadlock.
