#include "scanner/SourceScanner.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>
#include <sstream>
#include <string_view>

namespace dllscan {
namespace {

std::string trim(std::string value) {
    auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

int lineNumberAt(const std::string& text, std::size_t offset) {
    return 1 + static_cast<int>(std::count(text.begin(), text.begin() +
                                           static_cast<std::ptrdiff_t>(std::min(offset, text.size())),
                                           '\n'));
}

int columnNumberAt(const std::string& text, std::size_t offset) {
    std::size_t lineStart = text.rfind('\n', offset);
    if (lineStart == std::string::npos) lineStart = 0;
    else ++lineStart;
    return static_cast<int>(offset - lineStart) + 1;
}

std::vector<char> buildCodeMask(const std::string& text) {
    std::vector<char> code(text.size(), 1);
    enum State { Normal, LineComment, BlockComment, String, Char } state = Normal;

    for (std::size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        char next = i + 1 < text.size() ? text[i + 1] : '\0';

        switch (state) {
            case Normal:
                if (c == '/' && next == '/') {
                    code[i] = code[i + 1] = 0;
                    state = LineComment;
                    ++i;
                } else if (c == '/' && next == '*') {
                    code[i] = code[i + 1] = 0;
                    state = BlockComment;
                    ++i;
                } else if (c == '"') {
                    // Handle the common R"delim(...)delim" raw string form.
                    if (i > 0 && text[i - 1] == 'R') {
                        std::size_t delimiterStart = i + 1;
                        std::size_t openParen = delimiterStart;
                        while (openParen < text.size() &&
                               text[openParen] != '(' &&
                               openParen - delimiterStart <= 16) {
                            ++openParen;
                        }
                        if (openParen < text.size() && text[openParen] == '(') {
                            std::string delimiter =
                                text.substr(delimiterStart, openParen - delimiterStart);
                            std::string closing = ")" + delimiter + "\"";
                            std::size_t end = text.find(closing, openParen + 1);
                            if (end != std::string::npos) {
                                std::size_t maskStart = i - 1;
                                std::size_t maskEnd = end + closing.size();
                                for (std::size_t k = maskStart; k < maskEnd && k < code.size(); ++k) {
                                    code[k] = 0;
                                }
                                i = maskEnd - 1;
                                continue;
                            }
                        }
                    }
                    code[i] = 0;
                    state = String;
                } else if (c == '\'') {
                    code[i] = 0;
                    state = Char;
                }
                break;

            case LineComment:
                code[i] = 0;
                if (c == '\n') state = Normal;
                break;

            case BlockComment:
                code[i] = 0;
                if (c == '*' && next == '/') {
                    code[i + 1] = 0;
                    state = Normal;
                    ++i;
                }
                break;

            case String:
                code[i] = 0;
                if (c == '\\' && i + 1 < text.size()) {
                    code[i + 1] = 0;
                    ++i;
                } else if (c == '"') {
                    state = Normal;
                }
                break;

            case Char:
                code[i] = 0;
                if (c == '\\' && i + 1 < text.size()) {
                    code[i + 1] = 0;
                    ++i;
                } else if (c == '\'') {
                    state = Normal;
                }
                break;
        }
    }
    return code;
}

bool hasIgnoreComment(const std::string& text, std::size_t offset) {
    std::size_t lineStart = text.rfind('\n', offset);
    lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;
    std::size_t lineEnd = text.find('\n', offset);
    if (lineEnd == std::string::npos) lineEnd = text.size();

    std::size_t previousLineEnd = lineStart == 0 ? 0 : lineStart - 1;
    std::size_t previousLineStart = 0;
    if (lineStart > 1) {
        std::size_t previousNewline = text.rfind('\n', lineStart - 2);
        previousLineStart = previousNewline == std::string::npos ? 0 : previousNewline + 1;
    }

    std::string currentLine = text.substr(lineStart, lineEnd - lineStart);
    std::string previousLine = previousLineEnd > previousLineStart
        ? text.substr(previousLineStart, previousLineEnd - previousLineStart)
        : std::string();

    auto ignored = [](std::string line) {
        std::string upper;
        upper.reserve(line.size());
        for (unsigned char c : line) upper.push_back(static_cast<char>(std::toupper(c)));
        return upper.find("DLLSCAN-IGNORE") != std::string::npos ||
               upper.find("DLLGUARD-IGNORE") != std::string::npos;
    };
    return ignored(currentLine) || ignored(previousLine);
}

struct BalancedCall {
    std::string arguments;
    std::size_t openOffset = 0;
};

std::optional<BalancedCall> extractBalancedCall(const std::string& text, std::size_t openOffset) {
    if (openOffset >= text.size() || text[openOffset] != '(') return std::nullopt;

    int depth = 1;
    enum State { Normal, LineComment, BlockComment, String, Char } state = Normal;

    for (std::size_t i = openOffset + 1; i < text.size(); ++i) {
        char c = text[i];
        char next = i + 1 < text.size() ? text[i + 1] : '\0';

        switch (state) {
            case Normal:
                if (c == '/' && next == '/') { state = LineComment; ++i; }
                else if (c == '/' && next == '*') { state = BlockComment; ++i; }
                else if (c == '"') state = String;
                else if (c == '\'') state = Char;
                else if (c == '(') ++depth;
                else if (c == ')') {
                    --depth;
                    if (depth == 0) {
                        return BalancedCall{
                            text.substr(openOffset + 1, i - openOffset - 1),
                            openOffset,
                        };
                    }
                }
                break;
            case LineComment:
                if (c == '\n') state = Normal;
                break;
            case BlockComment:
                if (c == '*' && next == '/') { state = Normal; ++i; }
                break;
            case String:
                if (c == '\\') ++i;
                else if (c == '"') state = Normal;
                break;
            case Char:
                if (c == '\\') ++i;
                else if (c == '\'') state = Normal;
                break;
        }
    }
    return std::nullopt;
}

std::string firstTopLevelArgument(const std::string& arguments) {
    int parentheses = 0;
    int braces = 0;
    int brackets = 0;
    enum State { Normal, String, Char } state = Normal;

    for (std::size_t i = 0; i < arguments.size(); ++i) {
        char c = arguments[i];
        switch (state) {
            case Normal:
                if (c == '"') state = String;
                else if (c == '\'') state = Char;
                else if (c == '(') ++parentheses;
                else if (c == ')') --parentheses;
                else if (c == '{') ++braces;
                else if (c == '}') --braces;
                else if (c == '[') ++brackets;
                else if (c == ']') --brackets;
                else if (c == ',' && parentheses == 0 && braces == 0 && brackets == 0) {
                    return trim(arguments.substr(0, i));
                }
                break;
            case String:
                if (c == '\\') ++i;
                else if (c == '"') state = Normal;
                break;
            case Char:
                if (c == '\\') ++i;
                else if (c == '\'') state = Normal;
                break;
        }
    }
    return trim(arguments);
}

bool parseStringLiteralAt(const std::string& expression, std::size_t& position,
                           std::string& value) {
    while (position < expression.size() && std::isspace(static_cast<unsigned char>(expression[position]))) {
        ++position;
    }

    static const std::string prefixes[] = {"u8", "L", "u", "U"};
    for (const std::string& prefix : prefixes) {
        if (expression.compare(position, prefix.size(), prefix) == 0 &&
            position + prefix.size() < expression.size() &&
            expression[position + prefix.size()] == '"') {
            position += prefix.size();
            break;
        }
    }

    if (position >= expression.size() || expression[position] != '"') return false;
    ++position;

    while (position < expression.size()) {
        char c = expression[position++];
        if (c == '"') return true;
        if (c == '\\' && position < expression.size()) {
            char escaped = expression[position++];
            switch (escaped) {
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                case '\\': value.push_back('\\'); break;
                case '"': value.push_back('"'); break;
                default: value.push_back(escaped); break;
            }
        } else {
            value.push_back(c);
        }
    }
    return false;
}

std::optional<std::string> pureLiteralValueOptional(const std::string& expression) {
    std::size_t position = 0;
    std::string result;
    bool sawLiteral = false;

    while (true) {
        std::string part;
        if (!parseStringLiteralAt(expression, position, part)) {
            return sawLiteral ? std::optional<std::string>(result) : std::nullopt;
        }
        result += part;
        sawLiteral = true;

        while (position < expression.size() &&
               std::isspace(static_cast<unsigned char>(expression[position]))) {
            ++position;
        }
        if (position == expression.size()) return result;
    }
}

std::string firstLiteralAnywhere(const std::string& expression) {
    for (std::size_t i = 0; i < expression.size(); ++i) {
        if (expression[i] == '"') {
            std::size_t pos = i;
            std::string value;
            if (parseStringLiteralAt(expression, pos, value)) return value;
        }
    }
    return {};
}

std::vector<std::string> defaultApis() {
    return {
        "LoadLibraryA", "LoadLibraryW",
        "LoadLibraryExA", "LoadLibraryExW",
        "LoadLibrary", "LoadLibraryEx",
        "LoadPackagedLibrary",
        "LdrLoadDll",
    };
}

}  // namespace

std::vector<SourceCall> scanSourceFile(const std::filesystem::path& path,
                                       const std::vector<std::string>& extraApis) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};

    std::ostringstream buffer;
    buffer << file.rdbuf();
    const std::string text = buffer.str();

    std::vector<SourceCall> calls;
    const std::vector<char> codeMask = buildCodeMask(text);

    auto scanApiSet = [&](const std::vector<std::string>& inputApis,
                          bool searchPathConfiguration) {
        std::vector<std::string> apis = inputApis;
        std::sort(apis.begin(), apis.end());
        apis.erase(std::unique(apis.begin(), apis.end()), apis.end());

        std::string joined;
        for (std::size_t i = 0; i < apis.size(); ++i) {
            if (i) joined += '|';
            joined += apis[i];
        }
        if (joined.empty()) return;

        std::regex callRegex("\\b(" + joined + ")\\s*\\(");
        for (auto it = std::sregex_iterator(text.begin(), text.end(), callRegex);
             it != std::sregex_iterator(); ++it) {
            const std::smatch& match = *it;
            const std::size_t matchStart = static_cast<std::size_t>(match.position(0));
            if (matchStart >= codeMask.size() || !codeMask[matchStart]) continue;

            const std::string matchText = match.str(0);
            const std::size_t relativeParen = matchText.rfind('(');
            if (relativeParen == std::string::npos) continue;
            const std::size_t openOffset = matchStart + relativeParen;

            auto balanced = extractBalancedCall(text, openOffset);
            if (!balanced) continue;

            SourceCall call;
            call.api = match[1].str();
            call.file = path;
            call.line = lineNumberAt(text, openOffset);
            call.column = columnNumberAt(text, openOffset);
            call.argumentExpression = firstTopLevelArgument(balanced->arguments);
            call.isSearchPathConfiguration = searchPathConfiguration;
            call.suppressed = hasIgnoreComment(text, openOffset);

            auto literal = pureLiteralValueOptional(call.argumentExpression);
            call.literalIsComplete = literal.has_value();
            call.firstStringLiteral = literal.has_value()
                ? *literal
                : firstLiteralAnywhere(call.argumentExpression);

            const std::string allArgumentsUpper = [&] {
                std::string upper = balanced->arguments;
                std::transform(upper.begin(), upper.end(), upper.begin(),
                               [](unsigned char c) {
                                   return static_cast<char>(std::toupper(c));
                               });
                return upper;
            }();

            call.hasSearchFlags =
                allArgumentsUpper.find("LOAD_LIBRARY_SEARCH_") != std::string::npos;
            call.hasSafeFlag =
                allArgumentsUpper.find("LOAD_LIBRARY_SEARCH_SYSTEM32") != std::string::npos ||
                allArgumentsUpper.find("LOAD_LIBRARY_SEARCH_DEFAULT_DIRS") != std::string::npos;
            call.callsSafeWrapper =
                allArgumentsUpper.find("DLLGUARD") != std::string::npos ||
                match[1].str().find("Safe") != std::string::npos;

            calls.push_back(std::move(call));
        }
    };

    std::vector<std::string> loadApis = defaultApis();
    loadApis.insert(loadApis.end(), extraApis.begin(), extraApis.end());
    scanApiSet(loadApis, false);
    scanApiSet({"SetDllDirectoryA", "SetDllDirectoryW"}, true);

    return calls;
}

}  // namespace dllscan
