#include "scanner/PeParser.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dllscan {
namespace {

class Reader {
public:
    explicit Reader(std::vector<std::uint8_t> data) : data_(std::move(data)) {}

    const std::vector<std::uint8_t>& data() const { return data_; }
    std::size_t size() const { return data_.size(); }

    bool range(std::size_t offset, std::size_t length) const {
        if (length == 0) return true;
        if (offset > data_.size()) return false;
        return length <= data_.size() - offset;
    }

    std::uint16_t u16(std::size_t offset) const {
        return static_cast<std::uint16_t>(data_[offset]) |
               static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[offset + 1]) << 8);
    }

    std::uint32_t u32(std::size_t offset) const {
        return static_cast<std::uint32_t>(data_[offset]) |
               (static_cast<std::uint32_t>(data_[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(data_[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(data_[offset + 3]) << 24);
    }

    std::uint64_t u64(std::size_t offset) const {
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(data_[offset + i]) << (8 * i);
        }
        return value;
    }

    std::string cString(std::size_t offset, std::size_t maxLength = 4096) const {
        std::string result;
        while (offset < data_.size() && result.size() < maxLength) {
            char c = static_cast<char>(data_[offset]);
            if (c == '\0') break;
            result.push_back(c);
            ++offset;
        }
        return result;
    }

private:
    std::vector<std::uint8_t> data_;
};

struct Section {
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t rawAddress = 0;
    std::uint32_t rawSize = 0;
};

std::optional<std::size_t> rvaToOffset(const std::vector<Section>& sections,
                                        const Reader& reader,
                                        std::uint32_t rva) {
    if (rva < 4096 && rva < reader.size()) return static_cast<std::size_t>(rva);

    for (const Section& section : sections) {
        const std::uint64_t virtualEnd =
            static_cast<std::uint64_t>(section.virtualAddress) +
            std::max(section.virtualSize, section.rawSize);
        if (static_cast<std::uint64_t>(rva) >= section.virtualAddress &&
            static_cast<std::uint64_t>(rva) < virtualEnd) {
            const std::uint64_t offset = static_cast<std::uint64_t>(section.rawAddress) +
                                         (rva - section.virtualAddress);
            if (offset < reader.size()) return static_cast<std::size_t>(offset);
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> addressToOffset(const std::vector<Section>& sections,
                                           const Reader& reader,
                                           std::uint64_t address,
                                           bool rvaBased,
                                           std::uint64_t imageBase) {
    std::uint64_t rva64 = address;
    if (!rvaBased) {
        if (address < imageBase) return std::nullopt;
        rva64 = address - imageBase;
    }
    if (rva64 > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
    return rvaToOffset(sections, reader, static_cast<std::uint32_t>(rva64));
}

void parseImportThunks(const Reader& reader,
                       const std::vector<Section>& sections,
                       std::uint64_t tableAddress,
                       bool tableIsRva,
                       std::uint64_t imageBase,
                       bool is64Bit,
                       ImportedModule& module) {
    auto tableOffset = addressToOffset(sections, reader, tableAddress, tableIsRva, imageBase);
    if (!tableOffset) return;

    const std::size_t step = is64Bit ? 8 : 4;
    const std::uint64_t ordinalFlag = is64Bit ? 0x8000000000000000ULL : 0x80000000UL;

    for (std::size_t index = 0; index < 100000; ++index) {
        const std::size_t entryOffset = *tableOffset + index * step;
        if (!reader.range(entryOffset, step)) break;

        const std::uint64_t value = is64Bit ? reader.u64(entryOffset) : reader.u32(entryOffset);
        if (value == 0) break;

        ImportedFunction function;
        if ((value & ordinalFlag) != 0) {
            function.byOrdinal = true;
            function.ordinal = static_cast<std::uint16_t>(value & 0xffffU);
            function.name = "#" + std::to_string(function.ordinal);
        } else {
            auto nameOffset = addressToOffset(sections, reader, value, tableIsRva, imageBase);
            if (nameOffset && reader.range(*nameOffset + 2, 1)) {
                function.name = reader.cString(*nameOffset + 2);
            }
        }
        module.functions.push_back(std::move(function));
    }
}

void parseNormalImports(const Reader& reader,
                        const std::vector<Section>& sections,
                        std::size_t dataDirectoryOffset,
                        bool is64Bit,
                        std::uint64_t imageBase,
                        BinaryInfo& info) {
    if (!reader.range(dataDirectoryOffset, 8)) return;
    const std::uint32_t rva = reader.u32(dataDirectoryOffset);
    const std::uint32_t size = reader.u32(dataDirectoryOffset + 4);
    if (rva == 0 || size < 20) return;

    auto importOffset = rvaToOffset(sections, reader, rva);
    if (!importOffset) return;

    for (std::size_t index = 0; index < 4096; ++index) {
        const std::size_t descriptor = *importOffset + index * 20;
        if (!reader.range(descriptor, 20)) break;

        const std::uint32_t originalFirstThunk = reader.u32(descriptor);
        const std::uint32_t nameRva = reader.u32(descriptor + 12);
        const std::uint32_t firstThunk = reader.u32(descriptor + 16);
        if (nameRva == 0 && firstThunk == 0) break;

        ImportedModule module;
        module.delayLoaded = false;
        if (auto offset = rvaToOffset(sections, reader, nameRva)) {
            module.name = reader.cString(*offset);
        }

        const std::uint32_t thunkRva = originalFirstThunk ? originalFirstThunk : firstThunk;
        parseImportThunks(reader, sections, thunkRva, true, imageBase, is64Bit, module);
        info.imports.push_back(std::move(module));
    }
}

void parseDelayImports(const Reader& reader,
                       const std::vector<Section>& sections,
                       std::size_t dataDirectoryOffset,
                       bool is64Bit,
                       std::uint64_t imageBase,
                       BinaryInfo& info) {
    if (!reader.range(dataDirectoryOffset, 8)) return;
    const std::uint32_t rva = reader.u32(dataDirectoryOffset);
    const std::uint32_t size = reader.u32(dataDirectoryOffset + 4);
    if (rva == 0 || size < 32) return;

    auto baseOffset = rvaToOffset(sections, reader, rva);
    if (!baseOffset) return;

    for (std::size_t index = 0; index < 4096; ++index) {
        const std::size_t descriptor = *baseOffset + index * 32;
        if (!reader.range(descriptor, 32)) break;

        const std::uint32_t attributes = reader.u32(descriptor);
        const std::uint32_t nameAddress = reader.u32(descriptor + 4);
        const std::uint32_t intAddress = reader.u32(descriptor + 16);
        const std::uint32_t iatAddress = reader.u32(descriptor + 12);
        if (nameAddress == 0) break;

        const bool rvaBased = (attributes & 1U) != 0;

        ImportedModule module;
        module.delayLoaded = true;
        if (auto nameOffset = addressToOffset(sections, reader, nameAddress,
                                              rvaBased, imageBase)) {
            module.name = reader.cString(*nameOffset);
        }

        const std::uint64_t tableAddress = intAddress ? intAddress : iatAddress;
        parseImportThunks(reader, sections, tableAddress, rvaBased, imageBase, is64Bit, module);
        info.imports.push_back(std::move(module));
    }
}

bool looksLikeDllString(const std::string& value) {
    if (value.size() < 5) return false;
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower.find(".dll") != std::string::npos ||
           lower.find(".ocx") != std::string::npos ||
           lower.find(".cpl") != std::string::npos;
}

void extractStrings(const Reader& reader, BinaryInfo& info) {
    std::set<std::string> ascii;
    std::string current;

    for (std::uint8_t byte : reader.data()) {
        if (byte >= 0x20 && byte < 0x7f) {
            current.push_back(static_cast<char>(byte));
        } else {
            if (current.size() >= 5 && looksLikeDllString(current)) ascii.insert(current);
            current.clear();
        }
    }
    if (current.size() >= 5 && looksLikeDllString(current)) ascii.insert(current);
    info.asciiDllStrings.assign(ascii.begin(), ascii.end());

    std::set<std::string> utf16;
    const auto& data = reader.data();
    for (std::size_t parity = 0; parity < 2; ++parity) {
        std::string wide;
        for (std::size_t i = parity; i + 1 < data.size(); i += 2) {
            const std::uint16_t code = reader.u16(i);
            if (code >= 0x20 && code < 0x7f) {
                wide.push_back(static_cast<char>(code));
            } else {
                if (wide.size() >= 5 && looksLikeDllString(wide)) utf16.insert(wide);
                wide.clear();
            }
        }
        if (wide.size() >= 5 && looksLikeDllString(wide)) utf16.insert(wide);
    }
    info.utf16DllStrings.assign(utf16.begin(), utf16.end());
}

}  // namespace

BinaryInfo parsePeFile(const std::filesystem::path& path, bool extractDllStringsEnabled) {
    BinaryInfo result;
    result.path = path;

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        result.error = "cannot open file";
        return result;
    }

    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
    if (bytes.size() < 64) {
        result.error = "file is too small to be a PE image";
        return result;
    }

    Reader reader(std::move(bytes));
    if (reader.u16(0) != 0x5a4d) {
        result.error = "missing MZ signature";
        return result;
    }

    if (!reader.range(0x3c, 4)) {
        result.error = "missing PE header offset";
        return result;
    }
    const std::uint32_t peOffset = reader.u32(0x3c);
    if (!reader.range(peOffset, 24) || reader.u32(peOffset) != 0x00004550) {
        result.error = "missing PE signature";
        return result;
    }

    const std::size_t coff = peOffset + 4;
    const std::uint16_t numberOfSections = reader.u16(coff + 2);
    const std::uint16_t sizeOfOptionalHeader = reader.u16(coff + 16);
    result.machine = reader.u16(coff);
    result.isDynamicLinkLibrary = (reader.u16(coff + 18) & 0x2000U) != 0;

    const std::size_t optional = coff + 20;
    if (!reader.range(optional, sizeOfOptionalHeader) || sizeOfOptionalHeader < 96) {
        result.error = "invalid optional header";
        return result;
    }

    const std::uint16_t magic = reader.u16(optional);
    if (magic != 0x10b && magic != 0x20b) {
        result.error = "unsupported PE optional header magic";
        return result;
    }
    result.is64Bit = magic == 0x20b;
    result.subsystem = reader.u16(optional + 68);
    result.dllCharacteristics = reader.u16(optional + 70);

    const std::uint64_t imageBase = result.is64Bit ? reader.u64(optional + 24)
                                                    : reader.u32(optional + 28);
    const std::size_t dataDirectories = result.is64Bit ? optional + 112 : optional + 96;
    const std::size_t sectionTable = optional + sizeOfOptionalHeader;

    std::vector<Section> sections;
    sections.reserve(numberOfSections);
    for (std::uint16_t i = 0; i < numberOfSections; ++i) {
        const std::size_t header = sectionTable + static_cast<std::size_t>(i) * 40;
        if (!reader.range(header, 40)) break;
        Section section;
        section.virtualSize = reader.u32(header + 8);
        section.virtualAddress = reader.u32(header + 12);
        section.rawSize = reader.u32(header + 16);
        section.rawAddress = reader.u32(header + 20);
        sections.push_back(section);
    }

    parseNormalImports(reader, sections, dataDirectories + 1 * 8,
                       result.is64Bit, imageBase, result);
    parseDelayImports(reader, sections, dataDirectories + 13 * 8,
                      result.is64Bit, imageBase, result);

    const std::size_t loadConfigDirectory = dataDirectories + 10 * 8;
    if (reader.range(loadConfigDirectory, 8)) {
        const std::uint32_t loadConfigRva = reader.u32(loadConfigDirectory);
        const std::uint32_t loadConfigSize = reader.u32(loadConfigDirectory + 4);
        if (auto loadConfigOffset = rvaToOffset(sections, reader, loadConfigRva)) {
            const std::size_t flagsOffset = result.is64Bit ? 74 : 54;
            if (loadConfigSize >= flagsOffset + 2 &&
                reader.range(*loadConfigOffset + flagsOffset, 2)) {
                result.dependentLoadFlags = reader.u16(*loadConfigOffset + flagsOffset);
            }
        }
    }

    if (extractDllStringsEnabled) extractStrings(reader, result);

    result.parsed = true;
    return result;
}

}  // namespace dllscan
