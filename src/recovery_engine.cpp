#include "recovery_engine.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>

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
           std::equal(sig.begin(), sig.end(), b.begin() + static_cast<long long>(i));
}

uint64_t fileSize(HANDLE h) {
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(h, &li)) return 0;
    return static_cast<uint64_t>(li.QuadPart);
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
    size_ = fileSize(handle_);
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
    std::vector<uint8_t> buffer(CHUNK + 64);
    uint64_t offset = 0, lastReport = 0;
    auto started = std::chrono::steady_clock::now();

    while (offset < size_ && !cancel.load()) {
        DWORD want = static_cast<DWORD>(std::min<uint64_t>(CHUNK, size_ - offset));
        LARGE_INTEGER pos{}; pos.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(handle_, pos, nullptr, FILE_BEGIN)) {
            error = L"Failed to seek source."; return false;
        }
        DWORD got = 0;
        if (!ReadFile(handle_, buffer.data(), want, &got, nullptr)) {
            error = L"Read error while scanning the source."; return false;
        }
        if (!got) break;

        for (size_t i = 0; i < got; ++i) {
            if (cancel.load()) break;
            for (const auto& s : signatures) {
                if (!matchAt(buffer, i, s.bytes)) continue;
                // Skip RIFF false positives unless the following 4 bytes identify WEBP/AVI.
                if ((s.ext == L"webp" || s.ext == L"avi") && i + 12 <= got) {
                    const char* p = reinterpret_cast<const char*>(buffer.data() + i + 8);
                    std::string tag(p, p + 4);
                    if (s.ext == L"webp" && tag != "WEBP") continue;
                    if (s.ext == L"avi" && tag != "AVI ") continue;
                }
                RecoveryFile f;
                f.offset = offset + i;
                f.type = s.ext;
                f.confidence = s.confidence;
                // Conservative carving boundary. For filesystem-aware recovery, later versions
                // will parse NTFS/exFAT metadata and exact allocation chains.
                uint64_t maxSize = deep ? 1024ULL * 1024 * 1024 : 256ULL * 1024 * 1024;
                f.size = std::min<uint64_t>(maxSize, size_ - f.offset);
                f.path = L"recovered_" + std::to_wstring(f.offset) + L"." + f.type;
                if (cb) {
                    ScanStats st{offset + i, size_, 0, 0};
                    cb(st, &f);
                }
                ++i;
                break;
            }
        }
        offset += got;
        auto now = std::chrono::steady_clock::now();
        if (offset - lastReport >= 16 * 1024 * 1024 || offset >= size_) {
            double sec = std::chrono::duration<double>(now - started).count();
            ScanStats st{offset, size_, 0, sec > 0 ? (offset / 1048576.0) / sec : 0};
            if (cb) cb(st, nullptr);
            lastReport = offset;
        }
    }
    return !cancel.load();
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
        LARGE_INTEGER pos{}; pos.QuadPart = static_cast<LONGLONG>(posBytes);
        if (!SetFilePointerEx(handle_, pos, nullptr, FILE_BEGIN)) { error = L"Seek failed."; return false; }
        DWORD want = static_cast<DWORD>(std::min<uint64_t>(BUF, remaining));
        DWORD got = 0;
        if (!ReadFile(handle_, buf.data(), want, &got, nullptr) || got == 0) { error = L"Read failed during recovery."; return false; }
        dst.write(buf.data(), got);
        if (!dst) { error = L"Write failed."; return false; }
        posBytes += got; remaining -= got;
    }
    return true;
}
