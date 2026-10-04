# Recover My Files

Portable Windows file recovery tool focused on lost photos and videos.

## Goal

Run `Recovery.exe` directly from a USB drive. Do not install the application on the disk being recovered.

## Current engine

- Native C++20 / Win32
- Read-only source access
- Quick scan and deep raw-sector scan
- JPEG, PNG, WEBP, MP4/MOV, AVI, PDF and ZIP signatures
- Multi-threaded UI: scanning does not freeze the interface
- Recovery destination safety check
- Portable x64 Release build

## Important

Run as Administrator for physical-disk access. Recover to a different physical drive whenever possible.

A deep carve can recover file content after filesystem metadata is gone, but fragmented files may be incomplete. SSD TRIM can make deleted data unrecoverable.

## Roadmap

1. NTFS MFT deleted-file parser
2. NTFS resident/non-resident attribute recovery
3. exFAT/FAT32 directory and cluster-chain recovery
4. NTFS USN Journal analysis
5. JPEG/HEIC/MP4 structure validation and fragmented-file reconstruction
6. Thumbnail/preview generation
7. Disk-image scanning (RAW/IMG)
8. Pause/resume and scan session files
9. Hash-based duplicate detection
10. Signed portable release package

The architecture deliberately keeps filesystem-aware recovery separate from raw file carving so both methods can be combined.
