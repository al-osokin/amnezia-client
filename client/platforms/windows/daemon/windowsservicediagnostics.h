/* Diagnostic instrumentation for the Windows user-mode service only. */
#ifndef WINDOWS_SERVICE_DIAGNOSTICS_H
#define WINDOWS_SERVICE_DIAGNOSTICS_H

#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cwchar>
#include <cstdint>

#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
#include <shlobj.h>
#include <sddl.h>
#endif

namespace amnezia::diag {

// Only constant operation names and numeric metadata may enter this sink.
// Never pass addresses, configuration text, application paths or command lines.
inline void record(const char* phase, const char* operation, uint64_t id,
                   uint64_t elapsed, uint64_t a, uint64_t b, uint64_t c) {
#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
  const DWORD savedError = GetLastError();
  static SRWLOCK lock = SRWLOCK_INIT;
  AcquireSRWLockExclusive(&lock);
  static HANDLE file = []() {
    wchar_t root[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr,
                              SHGFP_TYPE_CURRENT, root))) {
      return INVALID_HANDLE_VALUE;
    }
    wchar_t path[MAX_PATH] = {};
    if (swprintf_s(path, L"%s\\AmneziaVPN-service-diag-%lu-%llu.log", root,
                   GetCurrentProcessId(), GetTickCount64()) < 0) {
      return INVALID_HANDLE_VALUE;
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1,
            &descriptor, nullptr)) {
      return INVALID_HANDLE_VALUE;
    }
    SECURITY_ATTRIBUTES attributes = {sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    // CREATE_NEW never opens/truncates a pre-existing file or follows its link.
    HANDLE opened = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    LocalFree(descriptor);
    return opened;
  }();
  static uint64_t size = 0;
  char line[512] = {};
  const int count = sprintf_s(line,
      "diag=v1 pid=%lu tid=%lu tick_ms=%llu phase=%s op=%s id=%llu elapsed_ms=%llu a=%llu b=%llu c=%llu\r\n",
      GetCurrentProcessId(), GetCurrentThreadId(), GetTickCount64(), phase,
      operation, id, elapsed, a, b, c);
  if (count > 0 && file != INVALID_HANDLE_VALUE) {
    // Bounded tail per service process. No network, driver calls or Qt logger.
    if (size + static_cast<uint64_t>(count) > 16 * 1024 * 1024) {
      LARGE_INTEGER zero = {};
      if (SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) && SetEndOfFile(file)) {
        size = 0;
      }
    }
    if (size + static_cast<uint64_t>(count) <= 16 * 1024 * 1024) {
      DWORD written = 0;
      WriteFile(file, line, static_cast<DWORD>(count), &written, nullptr);
      size += written;
    }
  }
  ReleaseSRWLockExclusive(&lock);
  SetLastError(savedError);
#else
  (void)phase; (void)operation; (void)id; (void)elapsed; (void)a; (void)b; (void)c;
#endif
}

class Scope final {
 public:
  explicit Scope(const char* operation, uint64_t a = 0, uint64_t b = 0,
                 uint64_t c = 0) : m_operation(operation) {
#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
    const DWORD savedError = GetLastError();
    static std::atomic<uint64_t> sequence{0};
    m_id = ++sequence;
    record("begin", m_operation, m_id, 0, a, b, c);
    m_started = GetTickCount64();
    SetLastError(savedError);
#endif
  }
  Scope(const Scope&) = delete;
  Scope& operator=(const Scope&) = delete;
  ~Scope() { if (!m_finished) finish("exit", 0, 0, 0); }

  void finish(const char* phase, uint64_t a, uint64_t b = 0, uint64_t c = 0) {
#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
    const DWORD savedError = GetLastError();
    const uint64_t elapsed = GetTickCount64() - m_started;
    record(phase, m_operation, m_id, elapsed, a, b, c);
    SetLastError(savedError);
#endif
    m_finished = true;
  }
 private:
  const char* m_operation;
  uint64_t m_id = 0;
  uint64_t m_started = 0;
  bool m_finished = false;
};

inline BOOL deviceIoControl(const char* operation, HANDLE device, DWORD code,
                           LPVOID input, DWORD inputSize, LPVOID output,
                           DWORD outputSize, LPDWORD returned, LPOVERLAPPED overlapped) {
  Scope call(operation, inputSize, outputSize, code);
  const BOOL ok = DeviceIoControl(device, code, input, inputSize, output,
                                  outputSize, returned, overlapped);
  const DWORD error = GetLastError(); // Before logging or any other Win32 call.
  call.finish("end", ok != FALSE, ok ? ERROR_SUCCESS : error,
              ok && returned ? *returned : 0);
  SetLastError(error); // Preserve the original caller-visible error even on success.
  return ok;
}

// IP Helper returns its error directly; GetLastError is not its result.
template<typename Function>
inline auto routeCall(const char* operation, Function function) {
  Scope call(operation);
  const auto result = function();
  const DWORD savedError = GetLastError();
  call.finish("end", result);
  SetLastError(savedError);
  return result;
}

} // namespace amnezia::diag
#endif
