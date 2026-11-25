#pragma once

#include "scanner/Types.h"

#include <string>

namespace dllscan {

std::string renderTextReport(const ScanReport& report);
std::string renderJsonReport(const ScanReport& report);
std::string renderSarifReport(const ScanReport& report);

}  // namespace dllscan
