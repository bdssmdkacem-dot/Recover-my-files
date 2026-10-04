#pragma once
#include <windows.h>
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct RecoveryRun {
    uint64_t diskOffset{};
    uint64_t length{};
    bool sparse{};
};

struct RecoveryFile {
    uint64_t offset{};
    uint64_t size{};
    std::wstring type;
    std::wstring path;
    int confidence{};
    std::vector<RecoveryRun> runs;
};

struct ScanStats {
    uint64_t bytesRead{};
    uint64_t totalBytes{};
    uint64_t filesFound{};
    double speedMBs{};
};

using ScanCallback = std::function<void(const ScanStats&, const RecoveryFile*)>;

class RecoveryEngine {
public:
    bool OpenPhysicalDrive(const std::wstring& drive, std::wstring& error);
    bool OpenVolume(const std::wstring& drive, std::wstring& error);
    void Close();
    bool Scan(bool deep, const std::atomic_bool& cancel, const ScanCallback& cb, std::wstring& error);
    bool Recover(const RecoveryFile& file, const std::wstring& destination, std::wstring& error);
    uint64_t Size() const { return size_; }
    const std::wstring& Source() const { return source_; }
private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    uint64_t size_ = 0;
    std::wstring source_;
    bool volume_ = false;
};
