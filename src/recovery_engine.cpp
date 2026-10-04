#include "recovery_engine.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
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

uint16_t le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint64_t le64(const uint8_t* p) {
    uint64_t v = 0; for (int i=0;i<8;++i) v |= static_cast<uint64_t>(p[i]) << (i*8); return v;
}
int64_t sle64(const uint8_t* p, size_t n) {
    uint64_t v=0; for(size_t i=0;i<n;++i) v|=static_cast<uint64_t>(p[i])<<(i*8);
    if(n<8 && (p[n-1]&0x80)) v |= ~0ULL << (n*8);
    return static_cast<int64_t>(v);
}
uint64_t deviceSize(HANDLE h) {
    GET_LENGTH_INFORMATION info{}; DWORD returned=0;
    if(DeviceIoControl(h,IOCTL_DISK_GET_LENGTH_INFO,nullptr,0,&info,sizeof(info),&returned,nullptr))
        return static_cast<uint64_t>(info.Length.QuadPart);
    LARGE_INTEGER li{}; return GetFileSizeEx(h,&li)&&li.QuadPart>0 ? static_cast<uint64_t>(li.QuadPart) : 0;
}
bool readAt(HANDLE h, uint64_t off, void* data, uint32_t bytes) {
    LARGE_INTEGER p{}; p.QuadPart=static_cast<LONGLONG>(off); DWORD got=0;
    return SetFilePointerEx(h,p,nullptr,FILE_BEGIN) && ReadFile(h,data,bytes,&got,nullptr) && got==bytes;
}
bool applyFixup(std::vector<uint8_t>& r, uint16_t sectorSize) {
    if(r.size()<24 || std::memcmp(r.data(),"FILE",4)!=0 || !sectorSize) return false;
    uint16_t usa=le16(r.data()+4), count=le16(r.data()+6);
    if(!usa || count<2 || static_cast<size_t>(usa)+count*2>r.size()) return false;
    uint16_t seq=le16(r.data()+usa);
    for(uint16_t i=1;i<count;++i) {
        size_t pos=static_cast<size_t>(i)*sectorSize-2;
        if(pos+2>r.size() || le16(r.data()+pos)!=seq) return false;
        std::memcpy(r.data()+pos,r.data()+usa+i*2,2);
    }
    return true;
}
struct NtfsBoot {
    uint16_t bytesPerSector{};
    uint8_t sectorsPerCluster{};
    int8_t clustersPerRecord{};
    int64_t mftCluster{};
    uint32_t recordSize{};
};
bool parseBoot(const std::vector<uint8_t>& b,NtfsBoot& n) {
    if(b.size()<512 || std::memcmp(b.data()+3,"NTFS    ",8)!=0) return false;
    n.bytesPerSector=le16(b.data()+11); n.sectorsPerCluster=b[13];
    n.mftCluster=static_cast<int64_t>(le64(b.data()+48));
    n.clustersPerRecord=static_cast<int8_t>(b[64]);
    if(!n.bytesPerSector || !n.sectorsPerCluster || !n.mftCluster) return false;
    n.recordSize=n.clustersPerRecord>0 ? static_cast<uint32_t>(n.clustersPerRecord)*n.bytesPerSector*n.sectorsPerCluster :
                 (1u<<static_cast<unsigned>(-n.clustersPerRecord));
    return n.recordSize>=512 && n.recordSize<=65536;
}
bool parseRunlist(const uint8_t* p,size_t len,uint64_t clusterSize,std::vector<RecoveryRun>& out) {
    if(!p || !len || !clusterSize) return false;

    size_t i=0;
    int64_t currentLcn=0;
    uint64_t logicalOffset=0;
    bool sawRun=false;

    while(i<len) {
        uint8_t h=p[i++];
        if(h==0) break;

        uint8_t lenBytes=h&0x0F;
        uint8_t offBytes=(h>>4)&0x0F;
        if(!lenBytes || lenBytes>8 || offBytes>8 || i+lenBytes+offBytes>len) return false;

        uint64_t clusters=0;
        for(uint8_t k=0;k<lenBytes;++k)
            clusters |= static_cast<uint64_t>(p[i++]) << (8*k);
        if(!clusters) return false;

        // A zero-sized LCN field denotes a sparse run. It occupies logical
        // clusters but has no physical allocation on disk.
        if(offBytes==0) {
            if(clusters > UINT64_MAX/clusterSize) return false;
            uint64_t bytes=clusters*clusterSize;
            out.push_back({0,bytes,true,logicalOffset});
            logicalOffset+=bytes; sawRun=true;
            continue;
        }

        int64_t delta=sle64(p+i,offBytes);
        i+=offBytes;

        if((delta>0 && currentLcn>INT64_MAX-delta) ||
           (delta<0 && currentLcn<INT64_MIN-delta))
            return false;
        currentLcn += delta;
        if(currentLcn<0) return false;

        uint64_t bytes=clusters*clusterSize;
        uint64_t lcn=static_cast<uint64_t>(currentLcn);
        if(lcn>UINT64_MAX/clusterSize) return false;
        uint64_t disk=lcn*clusterSize;

        out.push_back({disk,bytes,false,logicalOffset});
        logicalOffset+=bytes; sawRun=true;
    }

    return sawRun;
}
struct AttrInfo {
    std::vector<RecoveryRun> runs;
    uint64_t realSize=0;
    uint64_t residentOffset=0;
    std::vector<uint8_t> resident;
    bool compressed=false;
    bool encrypted=false;
    uint64_t compressionUnitSize=0;
};
bool findData(const std::vector<uint8_t>& rec,uint64_t clusterSize,AttrInfo& out) {
    if(rec.size()<24) return false;
    uint16_t first=le16(rec.data()+20); uint32_t used=le32(rec.data()+24);
    if(first>=rec.size() || used>rec.size()) return false;
    size_t p=first;
    while(p+16<=used) {
        uint32_t type=le32(rec.data()+p); if(type==0xFFFFFFFF) break;
        uint32_t len=le32(rec.data()+p+4); if(len<16 || p+len>used) break;
        if(type==0x80 && rec[p+8]==0) {
            uint16_t attrFlags=le16(rec.data()+p+12);
            out.compressed=(attrFlags&0x0001)!=0;
            out.encrypted=(attrFlags&0x4000)!=0;
            uint32_t valueLen=le32(rec.data()+p+16); uint16_t valueOff=le16(rec.data()+p+20);
            if(valueOff+valueLen<=len) {
                out.resident.assign(rec.begin()+p+valueOff,rec.begin()+p+valueOff+valueLen);
                out.residentOffset=p+valueOff;
                out.realSize=valueLen; return true;
            }
        } else if(type==0x80 && rec[p+8]!=0) {
            uint16_t attrFlags=le16(rec.data()+p+12);
            out.compressed=(attrFlags&0x0001)!=0;
            out.encrypted=(attrFlags&0x4000)!=0;
            uint64_t real=le64(rec.data()+p+48); uint16_t runOff=le16(rec.data()+p+32);
            if(runOff<len && parseRunlist(rec.data()+p+runOff,len-runOff,clusterSize,out.runs)) {
                out.realSize=real;
                if(out.compressed) out.compressionUnitSize=clusterSize*16ULL;
                return true;
            }
        }
        p+=len;
    }
    return false;
}
struct NameInfo { uint64_t parent=0; std::wstring name; uint8_t namespaceType=0; };

bool extractEfsMetadata(const std::vector<uint8_t>& rec,std::vector<uint8_t>& out) {
    if(rec.size()<24) return false;
    uint16_t first=le16(rec.data()+20); uint32_t used=le32(rec.data()+24);
    if(first>=rec.size()||used>rec.size()) return false;
    for(size_t p=first;p+16<=used;){
        uint32_t type=le32(rec.data()+p), len=le32(rec.data()+p+4);
        if(type==0xFFFFFFFF) break;
        if(len<16||p+len>used) break;
        if(type==0x80){
            uint8_t nonResident=rec[p+8];
            uint8_t nameLen=rec[p+9]; uint16_t nameOff=le16(rec.data()+p+10);
            if(nameLen==4 && nameOff+8<=len){
                const uint8_t* name=rec.data()+p+nameOff;
                const uint8_t efsName[8]={'$','\0','E','\0','F','\0','S','\0'};
                if(std::memcmp(name,efsName,8)==0 && !nonResident){
                    uint32_t valueLen=le32(rec.data()+p+16); uint16_t valueOff=le16(rec.data()+p+20);
                    if(valueOff+valueLen<=len){
                        out.assign(rec.begin()+p+valueOff,rec.begin()+p+valueOff+valueLen);
                        return !out.empty();
                    }
                }
            }
        }
        p+=len;
    }
    return false;
}

bool findName(const std::vector<uint8_t>& rec,NameInfo& out) {
    if(rec.size()<24) return false;
    uint16_t first=le16(rec.data()+20); uint32_t used=le32(rec.data()+24);
    if(first>=rec.size() || used>rec.size()) return false;

    bool found=false;
    NameInfo best{};
    int bestRank=99;

    size_t p=first;
    while(p+16<=used) {
        uint32_t type=le32(rec.data()+p);
        if(type==0xFFFFFFFF) break;
        uint32_t len=le32(rec.data()+p+4);
        if(len<16 || p+len>used) break;

        if(type==0x30 && rec[p+8]==0) {
            uint32_t valueLen=le32(rec.data()+p+16);
            uint16_t valueOff=le16(rec.data()+p+20);

            if(valueOff+valueLen<=len && valueLen>=66) {
                const uint8_t* v=rec.data()+p+valueOff;
                uint8_t nl=v[64];
                uint8_t ns=v[65];

                if(nl>0 && 66u+static_cast<uint32_t>(nl)*2u<=valueLen) {
                    NameInfo candidate{};
                    candidate.parent=le64(v)&0x0000FFFFFFFFFFFFULL;
                    candidate.name.assign(
                        reinterpret_cast<const wchar_t*>(v+66),
                        reinterpret_cast<const wchar_t*>(v+66+nl*2)
                    );
                    candidate.namespaceType=ns;

                    // Prefer Win32 (1), then Win32+DOS (3), then DOS (2),
                    // with POSIX (0) as the final fallback.
                    int rank = (ns==1) ? 0 : (ns==3) ? 1 : (ns==2) ? 2 : 3;
                    if(!found || rank<bestRank) {
                        best=std::move(candidate);
                        bestRank=rank;
                        found=true;
                        if(bestRank==0) break;
                    }
                }
            }
        }
        p+=len;
    }

    if(found) {
        out=std::move(best);
        return true;
    }
    return false;
}
std::wstring safePart(std::wstring s) {
    for(auto& c:s) if(c==L'<'||c==L'>'||c==L':'||c==L'"'||c==L'/'||c==L'\\'||c==L'|'||c==L'?'||c==L'*') c=L'_';
    while(!s.empty() && (s.back()==L'.'||s.back()==L' ')) s.pop_back();
    if(s.empty()) s=L"recovered";
    return s;
}
std::wstring buildPath(uint64_t id,const std::unordered_map<uint64_t,NameInfo>& names) {
    std::vector<std::wstring> parts; std::unordered_set<uint64_t> seen;
    uint64_t cur=id;
    while(cur && seen.insert(cur).second) {
        auto it=names.find(cur); if(it==names.end()) break;
        parts.push_back(safePart(it->second.name)); if(it->second.parent==cur) break; cur=it->second.parent;
        if(parts.size()>256) break;
    }
    std::wstring p;
    for(auto it=parts.rbegin();it!=parts.rend();++it) p+=L"\\"+*it;
    return p.empty()?L"\\Recovered":p;
}
bool lznt1Decompress(const uint8_t* src,size_t srcSize,uint8_t* dst,size_t dstCapacity,size_t& written) {
    written=0;
    if(!src || !srcSize || !dst || !dstCapacity) return false;
    using RtlDecompressBufferFn=LONG (WINAPI*)(USHORT,PVOID,ULONG,PVOID,ULONG,PULONG);
    static RtlDecompressBufferFn fn=[](){
        HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<RtlDecompressBufferFn>(GetProcAddress(ntdll,"RtlDecompressBuffer")) : nullptr;
    }();
    if(!fn) return false;
    ULONG out=0;
    constexpr USHORT COMPRESSION_FORMAT_LZNT1=0x0002;
    LONG st=fn(COMPRESSION_FORMAT_LZNT1,dst,static_cast<ULONG>(dstCapacity),
               const_cast<uint8_t*>(src),static_cast<ULONG>(srcSize),&out);
    if(st!=0) return false;
    written=out;
    return true;
}
bool readLogicalRange(HANDLE h,const std::vector<RecoveryRun>& runs,uint64_t logical,uint64_t length,std::vector<uint8_t>& out) {
    out.assign(static_cast<size_t>(length),0);
    uint64_t end=logical+length;
    if(end<logical) return false;
    for(const auto& r:runs){
        uint64_t rEnd=r.logicalOffset+r.length;
        if(rEnd<r.logicalOffset || rEnd<=logical || r.logicalOffset>=end) continue;
        uint64_t a=std::max(logical,r.logicalOffset), b=std::min(end,rEnd);
        uint64_t count=b-a;
        if(r.sparse) continue;
        uint64_t disk=r.diskOffset+(a-r.logicalOffset);
        if(disk>UINT64_MAX-count) return false;
        if(count>static_cast<uint64_t>(DWORD_MAX)) return false;
        if(!readAt(h,disk,out.data()+(a-logical),static_cast<uint32_t>(count))) return false;
    }
    return true;
}
bool recoverNtfsCompressed(HANDLE h,const RecoveryFile& file,std::ofstream& dst,uint64_t clusterSize,std::wstring& error) {
    if(file.runs.empty() || !clusterSize){error=L"Compressed NTFS file has no valid runlist.";return false;}
    const uint64_t unit=clusterSize*16ULL;
    if(!unit || unit>16ULL*1024*1024){error=L"Unsupported NTFS compression unit size.";return false;}
    uint64_t remaining=file.size, logical=0;
    std::vector<uint8_t> unitData;
    while(remaining){
        uint64_t want=std::min<uint64_t>(unit,remaining);
        if(!readLogicalRange(h,file.runs,logical,want,unitData)){error=L"Failed to read compressed NTFS unit.";return false;}
        bool allZero=std::all_of(unitData.begin(),unitData.end(),[](uint8_t v){return v==0;});
        if(allZero){
            dst.write(reinterpret_cast<const char*>(unitData.data()),static_cast<std::streamsize>(want));
            if(!dst){error=L"Write failed while restoring compressed sparse data.";return false;}
        } else {
            std::vector<uint8_t> decoded(static_cast<size_t>(unit));
            size_t written=0;
            if(lznt1Decompress(unitData.data(),unitData.size(),decoded.data(),decoded.size(),written)){
                if(written<want) std::fill(decoded.begin()+written,decoded.begin()+want,0);
                dst.write(reinterpret_cast<const char*>(decoded.data()),static_cast<std::streamsize>(want));
            } else {
                // An NTFS compression unit may be stored uncompressed when
                // compression does not save space. In that case its allocated
                // bytes are the logical bytes.
                dst.write(reinterpret_cast<const char*>(unitData.data()),static_cast<std::streamsize>(want));
            }
            if(!dst){error=L"Write failed while decompressing NTFS data.";return false;}
        }
        logical+=want; remaining-=want;
    }
    return true;
}
uint64_t estimateContainerSize(const std::vector<uint8_t>& b,size_t i,const std::wstring&type,uint64_t available,bool deep){
    const uint64_t cap=deep?4ULL*1024*1024*1024:512ULL*1024*1024;
    if(type==L"png") for(size_t p=i+8;p+12<=b.size();++p) if(b[p]=='I'&&b[p+1]=='E'&&b[p+2]=='N'&&b[p+3]=='D') return std::min<uint64_t>(available,std::min<uint64_t>(cap,(p+12)-i));
    if(type==L"jpg") for(size_t p=i+2;p+1<b.size();++p) if(b[p]==0xFF&&b[p+1]==0xD9) return std::min<uint64_t>(available,std::min<uint64_t>(cap,(p+2)-i));
    if(type==L"webp"||type==L"avi") if(i+8<=b.size()&&std::memcmp(b.data()+i,"RIFF",4)==0) return std::min<uint64_t>(available,std::min<uint64_t>(cap,8ULL+le32(b.data()+i+4)));
    return std::min<uint64_t>(available,cap);
}
}

bool RecoveryEngine::OpenPhysicalDrive(const std::wstring& drive,std::wstring& error){
    Close(); source_=drive; volume_=false;
    handle_=CreateFileW(drive.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(handle_==INVALID_HANDLE_VALUE){error=L"Cannot open source. Run Recovery.exe as Administrator and make sure the drive is accessible.";return false;}
    size_=deviceSize(handle_); if(!size_){Close();error=L"Cannot determine the source size.";return false;} return true;
}
bool RecoveryEngine::OpenVolume(const std::wstring& drive,std::wstring& error){
    Close(); source_=drive; volume_=true;
    handle_=CreateFileW(drive.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(handle_==INVALID_HANDLE_VALUE){error=L"Cannot open volume. Run Recovery.exe as Administrator.";return false;}
    size_=deviceSize(handle_); if(!size_){Close();error=L"Cannot determine the volume size.";return false;} return true;
}
void RecoveryEngine::Close(){if(handle_!=INVALID_HANDLE_VALUE)CloseHandle(handle_);handle_=INVALID_HANDLE_VALUE;size_=0;source_.clear();volume_=false;}

bool RecoveryEngine::Scan(bool deep,const std::atomic_bool& cancel,const ScanCallback& cb,std::wstring& error){
    if(handle_==INVALID_HANDLE_VALUE){error=L"No source selected.";return false;}
    if(volume_ && !deep){
        std::vector<uint8_t> boot(512);
        if(!readAt(handle_,0,boot.data(),512) || std::memcmp(boot.data()+3,"NTFS    ",8)!=0){
            error=L"Quick Scan currently supports NTFS volumes. Use Deep Scan for raw carving on this source."; return false;
        }
        NtfsBoot nb{}; if(!parseBoot(boot,nb)){error=L"Invalid NTFS boot sector.";return false;}
        const uint64_t cluster=static_cast<uint64_t>(nb.bytesPerSector)*nb.sectorsPerCluster;
        const uint64_t mftOffset=static_cast<uint64_t>(nb.mftCluster)*cluster;
        std::vector<uint8_t> rec(nb.recordSize);
        if(!readAt(handle_,mftOffset,rec.data(),nb.recordSize)||!applyFixup(rec,nb.bytesPerSector)){error=L"Cannot read the NTFS $MFT record.";return false;}
        AttrInfo mftData; if(!findData(rec,cluster,mftData)){error=L"Cannot read the NTFS $MFT runlist.";return false;}
        uint64_t recordCount=std::min<uint64_t>(mftData.realSize/nb.recordSize,10ULL*1024*1024);
        std::unordered_map<uint64_t,NameInfo> names; struct Pending{uint64_t id;std::vector<uint8_t> rec;};
        std::vector<Pending> pending; uint64_t scanned=0,found=0;
        for(const auto& run:mftData.runs){
            for(uint64_t pos=0;pos<run.length && scanned<recordCount;pos+=nb.recordSize,++scanned){
                if(cancel.load()) break;
                uint64_t off=run.diskOffset+pos; std::vector<uint8_t> r(nb.recordSize);
                if(!readAt(handle_,off,r.data(),nb.recordSize)||!applyFixup(r,nb.bytesPerSector)) continue;
                uint16_t flags=le16(r.data()+22);
                NameInfo ni; if(findName(r,ni)) names[scanned]=ni;
                if((flags & 0x0002) == 0 && (flags & 0x0001) == 0)
                    pending.push_back({scanned,std::move(r)});
            }
            if(cancel.load()) break;
        }
        for(const auto& q:pending){
            if(cancel.load()) break; uint16_t flags=le16(q.rec.data()+22);
            AttrInfo data; if(!findData(q.rec,cluster,data)||data.realSize==0) continue;
            if(data.realSize > 64ULL*1024*1024*1024) continue;
            NameInfo ni; auto nit=names.find(q.id); if(nit==names.end()) continue;
            RecoveryFile f{}; f.size=data.realSize; f.ntfsCompressed=data.compressed; f.ntfsEncrypted=data.encrypted; f.offset=data.runs.empty()?mftOffset+q.id*nb.recordSize:data.runs.front().diskOffset; f.type=L"file"; f.confidence=96; f.runs=std::move(data.runs);
            if(!data.resident.empty()){f.runs.clear();f.offset=mftOffset+q.id*nb.recordSize+data.residentOffset;f.size=data.resident.size();}
            f.path=buildPath(q.id,names)+L"/"+safePart(ni.name);
            auto dot=f.path.find_last_of(L'.'); if(dot!=std::wstring::npos && dot+1<f.path.size()) f.type=f.path.substr(dot+1);
            ++found; if(cb) cb(ScanStats{scanned*nb.recordSize,mftData.realSize,found,0},&f);
        }
        if(cancel.load()){error=L"Scan cancelled.";return false;}
        return true;
    }
    constexpr DWORD CHUNK=4*1024*1024; constexpr size_t OVERLAP=64;
    std::vector<uint8_t> buffer(CHUNK+OVERLAP); std::unordered_set<uint64_t> seen;
    uint64_t offset=0,lastReport=0,filesFound=0; auto started=std::chrono::steady_clock::now();
    while(offset<size_&&!cancel.load()){
        DWORD want=static_cast<DWORD>(std::min<uint64_t>(CHUNK,size_-offset)); LARGE_INTEGER pos{};pos.QuadPart=static_cast<LONGLONG>(offset);
        if(!SetFilePointerEx(handle_,pos,nullptr,FILE_BEGIN)){error=L"Failed to seek source.";return false;}
        DWORD got=0;if(!ReadFile(handle_,buffer.data(),want,&got,nullptr)){error=L"Read error while scanning the source.";return false;}if(!got)break;
        size_t scanBytes=got+(offset+got<size_?OVERLAP:0); if(scanBytes>got){LARGE_INTEGER next{};next.QuadPart=static_cast<LONGLONG>(offset+got);SetFilePointerEx(handle_,next,nullptr,FILE_BEGIN);DWORD extra=0;ReadFile(handle_,buffer.data()+got,OVERLAP,&extra,nullptr);}
        for(size_t i=0;i<scanBytes;++i){if(cancel.load())break;for(const auto&s:signatures){if(!matchAt(buffer,i,s.bytes))continue;
            if((s.ext==L"webp"||s.ext==L"avi")&&i+12<=scanBytes){const char*tag=reinterpret_cast<const char*>(buffer.data()+i+8);if(s.ext==L"webp"&&std::memcmp(tag,"WEBP",4)!=0)continue;if(s.ext==L"avi"&&std::memcmp(tag,"AVI ",4)!=0)continue;}
            uint64_t absolute=offset+i;if(!seen.insert(absolute).second)continue;RecoveryFile f{};f.offset=absolute;f.type=s.ext;f.confidence=s.confidence;f.size=estimateContainerSize(buffer,i,f.type,size_-f.offset,deep);f.path=L"recovered_"+std::to_wstring(f.offset)+L"."+f.type;++filesFound;if(cb)cb(ScanStats{absolute,size_,filesFound,0},&f);break;}}
        offset+=got;auto now=std::chrono::steady_clock::now();if(offset-lastReport>=16*1024*1024||offset>=size_){double sec=std::chrono::duration<double>(now-started).count();if(cb)cb(ScanStats{offset,size_,filesFound,sec>0?(offset/1048576.0)/sec:0},nullptr);lastReport=offset;}
    }
    if(cancel.load()){error=L"Scan cancelled.";return false;} return true;
}

bool RecoveryEngine::Recover(const RecoveryFile& file,const std::wstring& destination,std::wstring& error){
    if(handle_==INVALID_HANDLE_VALUE){error=L"No source selected.";return false;}
    std::filesystem::path outDir(destination);std::error_code ec;std::filesystem::create_directories(outDir,ec);if(ec){error=L"Cannot create destination folder.";return false;}
    std::filesystem::path out=outDir/file.path;std::filesystem::create_directories(out.parent_path(),ec);if(ec){error=L"Cannot create recovery subfolders.";return false;}
    std::ofstream dst(out,std::ios::binary);if(!dst){error=L"Cannot create recovery file.";return false;}
    constexpr DWORD BUF=4*1024*1024;std::vector<char> buf(BUF);
    if(file.ntfsCompressed){
        std::vector<uint8_t> boot(512); NtfsBoot nb{};
        if(!readAt(handle_,0,boot.data(),512)||!parseBoot(boot,nb)){error=L"Cannot determine NTFS cluster size for compressed recovery.";return false;}
        if(!recoverNtfsCompressed(handle_,file,dst,static_cast<uint64_t>(nb.bytesPerSector)*nb.sectorsPerCluster,error)) return false;
        return true;
    }
    if(file.runs.empty()){
        uint64_t remaining=file.size,posBytes=file.offset;while(remaining){LARGE_INTEGER pos{};pos.QuadPart=static_cast<LONGLONG>(posBytes);if(!SetFilePointerEx(handle_,pos,nullptr,FILE_BEGIN)){error=L"Seek failed.";return false;}DWORD want=static_cast<DWORD>(std::min<uint64_t>(BUF,remaining)),got=0;if(!ReadFile(handle_,buf.data(),want,&got,nullptr)||!got){error=L"Read failed during recovery.";return false;}dst.write(buf.data(),got);if(!dst){error=L"Write failed.";return false;}posBytes+=got;remaining-=got;}
        return true;
    }
    uint64_t remaining=file.size;
    for(const auto& run:file.runs){
        if(!remaining) break;
        uint64_t take=std::min<uint64_t>(remaining,run.length);

        if(run.sparse) {
            std::fill(buf.begin(),buf.end(),0);
            while(take) {
                DWORD want=static_cast<DWORD>(std::min<uint64_t>(BUF,take));
                dst.write(buf.data(),want);
                if(!dst){error=L"Write failed while restoring sparse data.";return false;}
                take-=want;
                remaining-=want;
            }
            continue;
        }

        uint64_t pos=run.diskOffset;
        while(take){
            LARGE_INTEGER p{};p.QuadPart=static_cast<LONGLONG>(pos);
            if(!SetFilePointerEx(handle_,p,nullptr,FILE_BEGIN)){error=L"Seek failed during fragmented recovery.";return false;}
            DWORD want=static_cast<DWORD>(std::min<uint64_t>(BUF,take)),got=0;
            if(!ReadFile(handle_,buf.data(),want,&got,nullptr)||!got){error=L"Read failed during fragmented recovery.";return false;}
            dst.write(buf.data(),got);
            if(!dst){error=L"Write failed.";return false;}
            pos+=got;take-=got;remaining-=got;
        }
    }
    if(remaining){error=L"File runlist is shorter than the file size.";return false;} return true;
}
