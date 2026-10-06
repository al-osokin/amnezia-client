#include "windowsservicediagnostics.h"
#include <cstdio>

int main() {
  SetLastError(12345);
  {
    amnezia::diag::Scope scope("test.scope", 1, 2, 3);
    if (GetLastError() != 12345) return 1;
    SetLastError(23456);
  }
  if (GetLastError() != 23456) return 2;
  const auto result = amnezia::diag::routeCall("test.route", []() {
    SetLastError(34567);
    return DWORD{87};
  });
  if (result != 87 || GetLastError() != 34567) return 3;
  DWORD returned = 0;
  // INVALID_HANDLE_VALUE cannot contact a driver. Check forwarding of failure.
  const BOOL ok = amnezia::diag::deviceIoControl("test.invalid_handle",
      INVALID_HANDLE_VALUE, 0, nullptr, 0, nullptr, 0, &returned, nullptr);
  if (ok || GetLastError() != ERROR_INVALID_HANDLE) return 4;
  puts("PASS: scope and API wrappers preserve return values and last error");
  printf("DIAG_TEST_PID=%lu\n", GetCurrentProcessId());
  return 0;
}
