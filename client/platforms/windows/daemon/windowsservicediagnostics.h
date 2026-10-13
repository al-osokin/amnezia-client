/* Diagnostic instrumentation for the Windows user-mode service only. */
#ifndef WINDOWS_SERVICE_DIAGNOSTICS_H
#define WINDOWS_SERVICE_DIAGNOSTICS_H

#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cstdint>
#include <mutex>
#include <thread>

#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
#include <shlobj.h>
#include <sddl.h>
#endif

namespace amnezia::diag {

#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
namespace detail {

constexpr uint64_t kMaxLogSize = 16 * 1024 * 1024;
constexpr DWORD kHeartbeatIntervalMs = 5000;
constexpr uint64_t kStallReportIntervalMs = 15000;

struct State {
  SRWLOCK lock = SRWLOCK_INIT;
  HANDLE log = INVALID_HANDLE_VALUE;
  HANDLE status = INVALID_HANDLE_VALUE;
  uint64_t logSize = 0;
  std::once_flag startOnce;
  std::thread watchdog;
  std::atomic<bool> stopping{false};
  std::atomic<uint64_t> sequence{0};
  std::atomic<uint64_t> lastBeginId{0};
  std::atomic<uint64_t> lastBeginTick{0};
  std::atomic<const char*> lastBeginOperation{nullptr};
  std::atomic<uint64_t> lastEndId{0};
  std::atomic<uint64_t> lastEndTick{0};
  std::atomic<const char*> lastEndOperation{nullptr};
  std::atomic<uint64_t> lastError{0};
  std::atomic<uint64_t> lastStallReportTick{0};

  ~State() {
    stopping.store(true, std::memory_order_release);
    if (watchdog.joinable()) {
      watchdog.join();
    }
    if (log != INVALID_HANDLE_VALUE) {
      CloseHandle(log);
    }
    if (status != INVALID_HANDLE_VALUE) {
      CloseHandle(status);
    }
  }
};

inline State& state() {
  static State value;
  return value;
}

inline HANDLE openFile(const wchar_t* suffix, DWORD disposition) {
  wchar_t root[MAX_PATH] = {};
  if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr,
                              SHGFP_TYPE_CURRENT, root))) {
    return INVALID_HANDLE_VALUE;
  }

  wchar_t path[MAX_PATH] = {};
  if (swprintf_s(path, L"%s\\AmneziaVPN-service-diag-%lu-%llu%s", root,
                 GetCurrentProcessId(), GetTickCount64(), suffix) < 0) {
    return INVALID_HANDLE_VALUE;
  }

  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &descriptor,
          nullptr)) {
    return INVALID_HANDLE_VALUE;
  }
  SECURITY_ATTRIBUTES attributes = {sizeof(SECURITY_ATTRIBUTES), descriptor,
                                    FALSE};
  HANDLE opened = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ,
                              &attributes, disposition, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
  LocalFree(descriptor);
  return opened;
}

inline HANDLE openStatusFile() {
  wchar_t root[MAX_PATH] = {};
  if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr,
                              SHGFP_TYPE_CURRENT, root))) {
    return INVALID_HANDLE_VALUE;
  }

  wchar_t path[MAX_PATH] = {};
  if (swprintf_s(path, L"%s\\AmneziaVPN-service-diag-status-%lu.txt", root,
                 GetCurrentProcessId()) < 0) {
    return INVALID_HANDLE_VALUE;
  }

  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &descriptor,
          nullptr)) {
    return INVALID_HANDLE_VALUE;
  }
  SECURITY_ATTRIBUTES attributes = {sizeof(SECURITY_ATTRIBUTES), descriptor,
                                    FALSE};
  HANDLE opened = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ,
                              &attributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
  LocalFree(descriptor);
  return opened;
}

inline void writeLine(State& s, const char* line, int count, bool flush) {
  if (count <= 0 || s.log == INVALID_HANDLE_VALUE) {
    return;
  }

  AcquireSRWLockExclusive(&s.lock);
  if (s.logSize + static_cast<uint64_t>(count) > kMaxLogSize) {
    LARGE_INTEGER zero = {};
    if (SetFilePointerEx(s.log, zero, nullptr, FILE_BEGIN) &&
        SetEndOfFile(s.log)) {
      s.logSize = 0;
    }
  }
  if (s.logSize + static_cast<uint64_t>(count) <= kMaxLogSize) {
    DWORD written = 0;
    if (WriteFile(s.log, line, static_cast<DWORD>(count), &written, nullptr)) {
      s.logSize += written;
      if (flush) {
        FlushFileBuffers(s.log);
      }
    }
  }
  ReleaseSRWLockExclusive(&s.lock);
}

inline void writeStatus(State& s) {
  if (s.status == INVALID_HANDLE_VALUE) {
    return;
  }

  const uint64_t now = GetTickCount64();
  const uint64_t beginId = s.lastBeginId.load(std::memory_order_acquire);
  const uint64_t beginTick = s.lastBeginTick.load(std::memory_order_acquire);
  const uint64_t endId = s.lastEndId.load(std::memory_order_acquire);
  const uint64_t endTick = s.lastEndTick.load(std::memory_order_acquire);
  const char* beginOperation =
      s.lastBeginOperation.load(std::memory_order_acquire);
  const char* endOperation = s.lastEndOperation.load(std::memory_order_acquire);
  const uint64_t age = beginTick != 0 && now >= beginTick ? now - beginTick : 0;

  char line[1024] = {};
  const int count = sprintf_s(
      line,
      "diag_status=v2 pid=%lu tick_ms=%llu heartbeat_ms=%lu "
      "last_begin_id=%llu last_begin_tick=%llu last_begin_op=%s "
      "last_end_id=%llu last_end_tick=%llu last_end_op=%s "
      "last_begin_age_ms=%llu last_error=%llu\r\n",
      GetCurrentProcessId(), now, kHeartbeatIntervalMs, beginId, beginTick,
      beginOperation ? beginOperation : "none", endId, endTick,
      endOperation ? endOperation : "none", age,
      s.lastError.load(std::memory_order_acquire));
  if (count <= 0) {
    return;
  }

  AcquireSRWLockExclusive(&s.lock);
  LARGE_INTEGER zero = {};
  if (SetFilePointerEx(s.status, zero, nullptr, FILE_BEGIN) &&
      SetEndOfFile(s.status)) {
    DWORD written = 0;
    WriteFile(s.status, line, static_cast<DWORD>(count), &written, nullptr);
    FlushFileBuffers(s.status);
  }
  ReleaseSRWLockExclusive(&s.lock);
}

inline void writeStallRecord(State& s, uint64_t now, uint64_t beginId,
                             const char* operation, uint64_t age,
                             uint64_t endId) {
  char line[512] = {};
  const int count = sprintf_s(
      line,
      "diag=v2 pid=%lu tid=%lu tick_ms=%llu phase=watchdog op=%s "
      "id=%llu elapsed_ms=%llu a=%llu b=%llu c=%llu\r\n",
      GetCurrentProcessId(), GetCurrentThreadId(), now,
      operation ? operation : "unknown", beginId, age, beginId, endId, 0ULL);
  writeLine(s, line, count, true);
}

inline void watchdogLoop(State* statePointer) {
  State& s = *statePointer;
  writeStatus(s);
  while (!s.stopping.load(std::memory_order_acquire)) {
    Sleep(kHeartbeatIntervalMs);
    if (s.stopping.load(std::memory_order_acquire)) {
      break;
    }

    writeStatus(s);
    const uint64_t now = GetTickCount64();
    const uint64_t beginId = s.lastBeginId.load(std::memory_order_acquire);
    const uint64_t beginTick = s.lastBeginTick.load(std::memory_order_acquire);
    const uint64_t endId = s.lastEndId.load(std::memory_order_acquire);
    if (beginId == 0 || beginId == endId || beginTick == 0 || now < beginTick) {
      continue;
    }

    const uint64_t age = now - beginTick;
    const uint64_t lastReport =
        s.lastStallReportTick.load(std::memory_order_acquire);
    if (age < kStallReportIntervalMs ||
        (lastReport != 0 && now - lastReport < kStallReportIntervalMs)) {
      continue;
    }
    s.lastStallReportTick.store(now, std::memory_order_release);
    writeStallRecord(s, now, beginId,
                     s.lastBeginOperation.load(std::memory_order_acquire), age,
                     endId);
  }
}

inline void ensureStarted() {
  State& s = state();
  std::call_once(s.startOnce, [&s]() {
    s.log = openFile(L".log", CREATE_NEW);
    s.status = openStatusFile();
    writeStatus(s);
    s.watchdog = std::thread(watchdogLoop, &s);
  });
}

inline uint64_t nextId() {
  ensureStarted();
  return ++state().sequence;
}

inline void markBegin(uint64_t id, const char* operation, uint64_t tick) {
  State& s = state();
  s.lastBeginOperation.store(operation, std::memory_order_release);
  s.lastBeginTick.store(tick, std::memory_order_release);
  s.lastBeginId.store(id, std::memory_order_release);
}

inline void markEnd(uint64_t id, const char* operation, uint64_t tick) {
  State& s = state();
  s.lastEndOperation.store(operation, std::memory_order_release);
  s.lastEndTick.store(tick, std::memory_order_release);
  s.lastEndId.store(id, std::memory_order_release);
}

}  // namespace detail
#endif

// Only constant operation names and numeric metadata may enter this sink.
// Never pass addresses, configuration text, application paths or command lines.
inline void record(const char* phase, const char* operation, uint64_t id,
                   uint64_t elapsed, uint64_t a, uint64_t b, uint64_t c) {
#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
  const DWORD savedError = GetLastError();
  detail::ensureStarted();
  char line[512] = {};
  const int count = sprintf_s(
      line,
      "diag=v2 pid=%lu tid=%lu tick_ms=%llu phase=%s op=%s id=%llu "
      "elapsed_ms=%llu a=%llu b=%llu c=%llu\r\n",
      GetCurrentProcessId(), GetCurrentThreadId(), GetTickCount64(), phase,
      operation, id, elapsed, a, b, c);

  const bool failedResult = std::strcmp(phase, "invalid") == 0 ||
                            (std::strcmp(phase, "end") == 0 &&
                             (b != 0 || a > 1));
  if (failedResult) {
    detail::state().lastError.store(b != 0 ? b : a, std::memory_order_release);
  }
  const bool flush = failedResult || elapsed >= 1000;
  detail::writeLine(detail::state(), line, count, flush);
  SetLastError(savedError);
#else
  (void)phase;
  (void)operation;
  (void)id;
  (void)elapsed;
  (void)a;
  (void)b;
  (void)c;
#endif
}

class Scope final {
 public:
  explicit Scope(const char* operation, uint64_t a = 0, uint64_t b = 0,
                 uint64_t c = 0)
      : m_operation(operation) {
#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
    const DWORD savedError = GetLastError();
    m_id = detail::nextId();
    m_started = GetTickCount64();
    detail::markBegin(m_id, m_operation, m_started);
    record("begin", m_operation, m_id, 0, a, b, c);
    SetLastError(savedError);
#endif
  }
  Scope(const Scope&) = delete;
  Scope& operator=(const Scope&) = delete;
  ~Scope() {
    if (!m_finished) {
      finish("exit", 0, 0, 0);
    }
  }

  void finish(const char* phase, uint64_t a, uint64_t b = 0,
              uint64_t c = 0) {
#ifdef AMNEZIA_SERVICE_DIAGNOSTICS
    const DWORD savedError = GetLastError();
    const uint64_t now = GetTickCount64();
    const uint64_t elapsed = now - m_started;
    record(phase, m_operation, m_id, elapsed, a, b, c);
    detail::markEnd(m_id, m_operation, now);
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
                            DWORD outputSize, LPDWORD returned,
                            LPOVERLAPPED overlapped) {
  Scope call(operation, inputSize, outputSize, code);
  const BOOL ok = DeviceIoControl(device, code, input, inputSize, output,
                                  outputSize, returned, overlapped);
  const DWORD error = GetLastError();
  call.finish("end", ok != FALSE, ok ? ERROR_SUCCESS : error,
              ok && returned ? *returned : 0);
  SetLastError(error);
  return ok;
}

// IP Helper returns its error directly; GetLastError is not its result.
template <typename Function>
inline auto routeCall(const char* operation, Function function) {
  Scope call(operation);
  const auto result = function();
  const DWORD savedError = GetLastError();
  call.finish("end", result);
  SetLastError(savedError);
  return result;
}

}  // namespace amnezia::diag
#endif
