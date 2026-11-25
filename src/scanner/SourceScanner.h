#pragma once

#include "scanner/Types.h"

namespace dllscan {

std::vector<SourceCall> scanSourceFile(const std::filesystem::path& path,
                                       const std::vector<std::string>& extraApis = {});

}  // namespace dllscan
