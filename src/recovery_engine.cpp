#include "recovery_engine.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_set>
#include <winioctl.h>

namespace {
struct Signature {
    std::wstring ext;
    std::vector<uint8_t> bytes;
    int confidence;
};

const std::vector<Signature> signatures = {
    {L"jpg",  {0xFF,0xD8,0xFF}, 95},
    {L"png",  {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A}, 98},
    {L"webp", {'R','I','F','F'}, 85},
    {L"mp4",  {0x66,0x74,0x79,0x70}, 75},
    {L"mov",  {0x66,0x74,0x79,0x70}, 75},
    {L"avi",  {'R','I','F','F'}, 80},
    {L"pdf",  {'%','P','D','F'}, 90},
    {L"zip",  {0x50,0x4B,0x03,0x04}, 92}
};

bool matchAt(const std::vector<uint8_t>& b, size_t i, const std::vector<uint8_t>& sig) {
    return i + sig.size() <= b.size() &&
           std::equal(sig.begin(), sig.end(), b.begin() + static_cast<std::ptrdiff_t>(i));
}

uint64_t deviceSize(HANDLE h) {
    GET_LENGTH_INFORMATION info{};
    DWORD returned = 0;
    if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                        &info, sizeof(info), &returned, nullptr)) {
        return static_cast<uint64_t>(info.Length.QuadPart);
    }

    LARGE_INTEGER li{};
    if (GetFileSizeEx(h, &li) && li.QuadPart > 0) {
        return static_cast<uint64_t>(li.QuadPart);
    }
    return 0;
}

uint32_t le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

uint64_t estimateContainerSize(const std::vector<uint8_t>& b, size_t i,
                               const std::wstring& type, uint64_t available,
                               bool deep) {
    const uint64_t cap = deep ? 4ULL * 1024 * 1024 * 1024 : 512ULL * 1024 * 1024;

    if (type == L"png") {
        for (size_t p = i + 8; p + 12 <= b.size(); ++p) {
            if (b[p] == 'I' && b[p+1] == 'E' && b[p+2] == 'N' && b[p+3] == 'D') {
                return std::min<uint64_t>(available, std::min<uint64_t>(cap, (p + 12) - i));
            }
        }
    }

    if (type == L"jpg") {
        for (size_t p = i + 2; p + 1 < b.size(); ++p) {
            if (b[p] == 0xFF && b[p+1] == 0xD9) {
                return std::min<uint64_t>(available, std::min<uint64_t>(cap, (p + 2) - i));
            }
        }
    }

    if (type == L"webp" || type == L"avi") {
        if (i + 8 <= b.size() && std::memcmp(b.data() + i, "RIFF", 4) == 0) {
            uint64_t n = 8ULL + le32(b.data() + i + 4);
            return std::min<uint64_t>(available, std::min<uint64_t>(cap, n));
        }
    }

    if (type == L"mp4" || type == L"mov") {
        // ftyp is normally inside the first ISO-BMFF box. Recover the first box span
        // when it is available; otherwise keep a conservative bounded candidate.
        if (i >= 4) {
            uint32_t box = le32(b.data() + i - 4);
            if (box >= 16 && box <= cap) {
                return std::min<uint64_t>(available, box);
            }
        }
    }

    return std::min<uint64_t>(available, cap);
}
}

bool RecoveryEngine::OpenPhysicalDrive(const std::wstring& drive, std::wstring& error) {
    Close();
    source_ = drive;
    handle_ = CreateFileW(drive.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
        error = L"Cannot open source. Run Recovery.exe as Administrator and make sure the drive is accessible.";
        return false;
    }
    size_ = deviceSize(handle_);
    if (size_ == 0) {
        Close();
        error = L"Cannot determine the source size.";
        return false;
    }
    return true;
}

bool RecoveryEngine::OpenVolume(const std::wstring& drive, std::wstring& error) {
    return OpenPhysicalDrive(drive, error);
}

void RecoveryEngine::Close() {
    if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    handle_ = INVALID_HANDLE_VALUE;
    size_ = 0;
    source_.clear();
}

bool RecoveryEngine::Scan(bool deep, const std::atomic_bool& cancel, const ScanCallback& cb, std::wstring& error) {
    if (handle_ == INVALID_HANDLE_VALUE) { error = L"No source selected."; return false; }

    constexpr DWORD CHUNK = 4 * 1024 * 1024;
    constexpr size_t OVERLAP = 64;
    std::vector<uint8_t> buffer(CHUNK + OVERLAP);
    std::unordered_set<uint64_t> seen;
    uint64_t offset = 0, lastReport = 0, filesFound = 0;
    auto started = std::chrono::steady_clock::now();

    while (offset < size_ && !cancel.load()) {
        const uint64_t remaining = size_ - offset;
        const DWORD want = static_cast<DWORD>(std::min<uint64_t>(CHUNK, remaining));

        LARGE_INTEGER pos{};
        pos.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(handle_, pos, nullptr, FILE_BEGIN)) {
            error = L"Failed to seek source.";
            return false;
        }

        DWORD got = 0;
        if (!ReadFile(handle_, buffer.data(), want, &got, nullptr)) {
            error = L"Read error while scanning the source.";
            return false;
        }
        if (!got) break;

        const size_t scanBytes = static_cast<size_t>(got) + (offset + got < size_ ? OVERLAP : 0);
        if (scanBytes > got) {
            LARGE_INTEGER next{};
            next.QuadPart = static_cast<LONGLONG>(offset + got);
            SetFilePointerEx(handle_, next, nullptr, FILE_BEGIN);
            DWORD extra = 0;
            ReadFile(handle_, buffer.data() + got, static_cast<DWORD>(OVERLAP), &extra, nullptr);
        }

        for (size_t i = 0; i < scanBytes; ++i) {
            if (cancel.load()) break;
            for (const auto& s : signatures) {
                if (!matchAt(buffer, i, s.bytes)) continue;

                if ((s.ext == L"webp" || s.ext == L"avi") && i + 12 <= scanBytes) {
                    const char* tag = reinterpret_cast<const char*>(buffer.data() + i + 8);
                    if (s.ext == L"webp" && std::memcmp(tag, "WEBP", 4) != 0) continue;
                    if (s.ext == L"avi" && std::memcmp(tag, "AVI ", 4) != 0) continue;
                }

                const uint64_t absolute = offset + i;
                if (!seen.insert(absolute).second) continue;

                RecoveryFile f;
                f.offset = absolute;
                f.type = s.ext;
                f.confidence = s.confidence;
                f.size = estimateContainerSize(
                    buffer, i, f.type, size_ - f.offset, deep);
                f.path = L"recovered_" + std::to_wstring(f.offset) + L"." + f.type;

                ++filesFound;
                if (cb) {
                    ScanStats st{absolute, size_, filesFound, 0};
                    cb(st, &f);
                }
                break;
            }
        }

        offset += got;
        auto now = std::chrono::steady_clock::now();
        if (offset - lastReport >= 16 * 1024 * 1024 || offset >= size_) {
            double sec = std::chrono::duration<double>(now - started).count();
            ScanStats st{offset, size_, filesFound,
                          sec > 0 ? (offset / 1048576.0) / sec : 0};
            if (cb) cb(st, nullptr);
            lastReport = offset;
        }
    }

    if (cancel.load()) {
        error = L"Scan cancelled.";
        return false;
    }
    return true;
}

bool RecoveryEngine::Recover(const RecoveryFile& file, const std::wstring& destination, std::wstring& error) {
    if (handle_ == INVALID_HANDLE_VALUE) { error = L"No source selected."; return false; }

    std::filesystem::path outDir(destination);
    std::error_code ec;
    std::filesystem::create_directories(outDir, ec);
    if (ec) { error = L"Cannot create destination folder."; return false; }

    std::filesystem::path out = outDir / file.path;
    std::ofstream dst(out, std::ios::binary);
    if (!dst) { error = L"Cannot create recovery file."; return false; }

    constexpr DWORD BUF = 4 * 1024 * 1024;
    std::vector<char> buf(BUF);
    uint64_t remaining = file.size, posBytes = file.offset;
    while (remaining) {
        LARGE_INTEGER pos{};
        pos.QuadPart = static_cast<LONGLONG>(posBytes);
        if (!SetFilePointerEx(handle_, pos, nullptr, FILE_BEGIN)) {
            error = L"Seek failed.";
            return false;
        }
        DWORD want = static_cast<DWORD>(std::min<uint64_t>(BUF, remaining));
        DWORD got = 0;
        if (!ReadFile(handle_, buf.data(), want, &got, nullptr) || got == 0) {
            error = L"Read failed during recovery.";
            return false;
        }
        dst.write(buf.data(), got);
        if (!dst) { error = L"Write failed."; return false; }
        posBytes += got;
        remaining -= got;
    }
    return true;
}
