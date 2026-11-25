#pragma once

#include "scanner/Types.h"

namespace dllscan {

BinaryInfo parsePeFile(const std::filesystem::path& path, bool extractDllStrings = true);

}  // namespace dllscan
