#include "scanner/Report.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace dllscan {
namespace {

std::string jsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    out += buffer;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string q(const std::string& value) {
    return "\"" + jsonEscape(value) + "\"";
}

std::string indent(int depth) {
    return std::string(static_cast<std::size_t>(depth) * 2, ' ');
}

void appendMetadata(std::ostringstream& out, const std::map<std::string, std::string>& metadata,
                    int depth, bool trailingComma) {
    if (metadata.empty()) {
        out << indent(depth) << "\"metadata\": {}";
    } else {
        out << indent(depth) << "\"metadata\": {\n";
        std::size_t index = 0;
        for (const auto& [key, value] : metadata) {
            out << indent(depth + 1) << q(key) << ": " << q(value);
            if (++index != metadata.size()) out << ',';
            out << '\n';
        }
        out << indent(depth) << "}";
    }
    if (trailingComma) out << ',';
    out << '\n';
}

}  // namespace

std::string renderTextReport(const ScanReport& report) {
    std::ostringstream out;
    out << "DllGuard scanner " << report.toolVersion << "\n";
    out << "PE binaries scanned: " << report.binaries.size() << "\n";
    out << "Source loader/config sites: " << report.sourceCalls.size() << "\n\n";

    std::vector<Finding> findings = report.findings;
    std::sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        if (severityRank(a.severity) != severityRank(b.severity)) {
            return severityRank(a.severity) > severityRank(b.severity);
        }
        if (a.file != b.file) return a.file < b.file;
        return a.location < b.location;
    });

    for (const auto& finding : findings) {
        std::string sev = severityName(finding.severity);
        std::transform(sev.begin(), sev.end(), sev.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        out << '[' << sev << "] " << finding.ruleId << " - " << finding.title << '\n';
        out << "  Location: " << (finding.location.empty() ? finding.file : finding.location) << '\n';
        out << "  " << finding.detail << '\n';
        out << "  Fix: " << finding.recommendation << "\n\n";
    }

    out << "Summary:";
    for (const char* key : {"critical", "high", "medium", "low", "info"}) {
        auto it = report.countsBySeverity.find(key);
        out << ' ' << key << '=' << (it == report.countsBySeverity.end() ? 0 : it->second);
    }
    out << "\n";
    return out.str();
}

std::string renderJsonReport(const ScanReport& report) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"schemaVersion\": " << report.schemaVersion << ",\n";
    out << "  \"tool\": \"dllscan\",\n";
    out << "  \"toolVersion\": " << q(report.toolVersion) << ",\n";

    out << "  \"summary\": {";
    bool first = true;
    for (const char* key : {"critical", "high", "medium", "low", "info"}) {
        if (!first) out << ", ";
        first = false;
        auto it = report.countsBySeverity.find(key);
        out << q(key) << ": " << (it == report.countsBySeverity.end() ? 0 : it->second);
    }
    out << "},\n";

    out << "  \"binaries\": [\n";
    for (std::size_t bi = 0; bi < report.binaries.size(); ++bi) {
        const BinaryInfo& binary = report.binaries[bi];
        out << "    {\n";
        out << "      \"path\": " << q(binary.path.string()) << ",\n";
        out << "      \"parsed\": " << (binary.parsed ? "true" : "false") << ",\n";
        if (!binary.error.empty()) out << "      \"error\": " << q(binary.error) << ",\n";
        out << "      \"is64Bit\": " << (binary.is64Bit ? "true" : "false") << ",\n";
        out << "      \"isDll\": " << (binary.isDynamicLinkLibrary ? "true" : "false") << ",\n";
        out << "      \"dependentLoadFlags\": ";
        if (binary.dependentLoadFlags) out << *binary.dependentLoadFlags;
        else out << "null";
        out << ",\n";

        out << "      \"imports\": [\n";
        for (std::size_t mi = 0; mi < binary.imports.size(); ++mi) {
            const ImportedModule& module = binary.imports[mi];
            out << "        {\"name\": " << q(module.name)
                << ", \"delayLoaded\": " << (module.delayLoaded ? "true" : "false")
                << ", \"functions\": [";
            for (std::size_t fi = 0; fi < module.functions.size(); ++fi) {
                if (fi) out << ", ";
                out << q(module.functions[fi].name);
            }
            out << "]}";
            if (mi + 1 != binary.imports.size()) out << ',';
            out << '\n';
        }
        out << "      ],\n";

        out << "      \"asciiDllStrings\": [";
        for (std::size_t i = 0; i < binary.asciiDllStrings.size(); ++i) {
            if (i) out << ", ";
            out << q(binary.asciiDllStrings[i]);
        }
        out << "],\n";
        out << "      \"utf16DllStrings\": [";
        for (std::size_t i = 0; i < binary.utf16DllStrings.size(); ++i) {
            if (i) out << ", ";
            out << q(binary.utf16DllStrings[i]);
        }
        out << "]\n";

        out << "    }";
        if (bi + 1 != report.binaries.size()) out << ',';
        out << '\n';
    }
    out << "  ],\n";

    out << "  \"sourceCalls\": [\n";
    for (std::size_t i = 0; i < report.sourceCalls.size(); ++i) {
        const SourceCall& call = report.sourceCalls[i];
        out << "    {";
        out << "\"file\": " << q(call.file.string())
            << ", \"line\": " << call.line
            << ", \"column\": " << call.column
            << ", \"api\": " << q(call.api)
            << ", \"argumentExpression\": " << q(call.argumentExpression)
            << ", \"literal\": " << q(call.firstStringLiteral)
            << ", \"literalIsComplete\": " << (call.literalIsComplete ? "true" : "false")
            << ", \"hasSearchFlags\": " << (call.hasSearchFlags ? "true" : "false")
            << ", \"hasSafeFlag\": " << (call.hasSafeFlag ? "true" : "false")
            << ", \"searchPathConfiguration\": "
            << (call.isSearchPathConfiguration ? "true" : "false")
            << ", \"suppressed\": " << (call.suppressed ? "true" : "false");
        out << "}";
        if (i + 1 != report.sourceCalls.size()) out << ',';
        out << '\n';
    }
    out << "  ],\n";

    out << "  \"findings\": [\n";
    for (std::size_t i = 0; i < report.findings.size(); ++i) {
        const Finding& f = report.findings[i];
        out << "    {\n";
        out << "      \"ruleId\": " << q(f.ruleId) << ",\n";
        out << "      \"severity\": " << q(severityName(f.severity)) << ",\n";
        out << "      \"title\": " << q(f.title) << ",\n";
        out << "      \"detail\": " << q(f.detail) << ",\n";
        out << "      \"recommendation\": " << q(f.recommendation) << ",\n";
        out << "      \"file\": " << q(f.file) << ",\n";
        out << "      \"location\": " << q(f.location) << ",\n";
        appendMetadata(out, f.metadata, 3, false);
        out << "    }";
        if (i + 1 != report.findings.size()) out << ',';
        out << '\n';
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

std::string renderSarifReport(const ScanReport& report) {
    std::map<std::string, int> ruleIndex;
    std::vector<std::string> rules;
    for (const Finding& finding : report.findings) {
        if (!ruleIndex.count(finding.ruleId)) {
            ruleIndex[finding.ruleId] = static_cast<int>(rules.size());
            rules.push_back(finding.ruleId);
        }
    }

    std::ostringstream out;
    out << "{\n";
    out << "  \"version\": \"2.1.0\",\n";
    out << "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n";
    out << "  \"runs\": [{\n";
    out << "    \"tool\": {\"driver\": {\n";
    out << "      \"name\": \"dllscan\",\n";
    out << "      \"version\": " << q(report.toolVersion) << ",\n";
    out << "      \"rules\": [\n";
    for (std::size_t i = 0; i < rules.size(); ++i) {
        out << "        {\"id\": " << q(rules[i]) << "}";
        if (i + 1 != rules.size()) out << ',';
        out << '\n';
    }
    out << "      ]\n";
    out << "    }},\n";
    out << "    \"results\": [\n";

    for (std::size_t i = 0; i < report.findings.size(); ++i) {
        const Finding& f = report.findings[i];
        const char* level = f.severity >= Severity::High ? "error"
                            : f.severity == Severity::Medium ? "warning" : "note";
        out << "      {";
        out << "\"ruleId\": " << q(f.ruleId)
            << ", \"ruleIndex\": " << ruleIndex[f.ruleId]
            << ", \"level\": " << q(level)
            << ", \"message\": {\"text\": " << q(f.title + ". " + f.detail) << "}"
            << ", \"locations\": [{";
        out << "\"physicalLocation\": {\"artifactLocation\": {\"uri\": " << q(f.file) << "}";
        if (auto line = f.metadata.find("line"); line != f.metadata.end()) {
            out << ", \"region\": {\"startLine\": " << line->second << "}";
        }
        out << "}}]";
        out << "}";
        if (i + 1 != report.findings.size()) out << ',';
        out << '\n';
    }

    out << "    ]\n";
    out << "  }]\n";
    out << "}\n";
    return out.str();
}

}  // namespace dllscan
