#include "recovery_engine.h"
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <atomic>
#include <thread>
#include <vector>

#pragma comment(lib, "comctl32.lib")

static HWND g_list{}, g_status{}, g_progress{}, g_scan{}, g_recover{}, g_deep{};
static RecoveryEngine g_engine;
static std::vector<RecoveryFile> g_files;
static std::atomic_bool g_cancel{false};
static std::thread g_worker;

enum : int { IDC_DRIVE=1001, IDC_SCAN=1002, IDC_DEEP=1003, IDC_LIST=1004, IDC_RECOVER=1005, IDC_STATUS=1006, IDC_PROGRESS=1007 };

void status(const std::wstring& s) { SetWindowTextW(g_status, s.c_str()); }

void scan(HWND hwnd, bool deep) {
    if (g_worker.joinable()) return;
    wchar_t drive[32]{};
    GetWindowTextW(GetDlgItem(hwnd, IDC_DRIVE), drive, 32);
    if (!*drive) { status(L"Select a drive first."); return; }

    std::wstring error;
    if (!g_engine.OpenPhysicalDrive(drive, error)) { status(error); return; }

    g_files.clear();
    ListView_DeleteAllItems(g_list);
    g_cancel = false;
    EnableWindow(g_scan, FALSE);
    EnableWindow(g_deep, FALSE);
    EnableWindow(g_recover, FALSE);

    g_worker = std::thread([hwnd, deep]() {
        std::wstring error;
        bool ok = g_engine.Scan(deep, g_cancel, [&](const ScanStats& st, const RecoveryFile* f) {
            if (f) {
                g_files.push_back(*f);
                PostMessageW(hwnd, WM_APP + 1, 0, static_cast<LPARAM>(g_files.size() - 1));
            }
            PostMessageW(hwnd, WM_APP + 2, static_cast<WPARAM>(st.bytesRead), static_cast<LPARAM>(st.totalBytes));
        }, error);
        PostMessageW(hwnd, WM_APP + 3, ok ? 1 : 0, 0);
    });
}

void recoverSelected(HWND hwnd) {
    int i = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (i < 0 || i >= static_cast<int>(g_files.size())) { status(L"Select a file to recover."); return; }

    BROWSEINFOW bi{}; bi.hwndOwner = hwnd; bi.lpszTitle = L"Choose a recovery destination on another drive";
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;
    wchar_t path[MAX_PATH]{};
    SHGetPathFromIDListW(pidl, path);
    CoTaskMemFree(pidl);
    if (!*path) return;

    if (g_engine.Source().size() >= 2 && _wcsnicmp(g_engine.Source().c_str(), path, 2) == 0) {
        status(L"Safety stop: choose a different drive than the source.");
        return;
    }
    std::wstring err;
    if (g_engine.Recover(g_files[i], path, err)) status(L"Recovered successfully.");
    else status(err);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE: {
        CreateWindowW(L"STATIC", L"Source drive:", WS_CHILD|WS_VISIBLE, 16,16,100,24,hwnd,nullptr,nullptr,nullptr);
        HWND combo=CreateWindowW(L"COMBOBOX", L"", WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST, 115,13,180,250,hwnd,(HMENU)IDC_DRIVE,nullptr,nullptr);
        wchar_t drives[512]{}; GetLogicalDriveStringsW(511, drives);
        for (wchar_t* p=drives; *p; p+=wcslen(p)+1) SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)p);
        SendMessageW(combo, CB_SETCURSEL, 0, 0);

        g_scan=CreateWindowW(L"BUTTON",L"Quick Scan",WS_CHILD|WS_VISIBLE,310,13,110,30,hwnd,(HMENU)IDC_SCAN,nullptr,nullptr);
        g_deep=CreateWindowW(L"BUTTON",L"Deep Scan",WS_CHILD|WS_VISIBLE,430,13,110,30,hwnd,(HMENU)IDC_DEEP,nullptr,nullptr);
        g_recover=CreateWindowW(L"BUTTON",L"Recover Selected",WS_CHILD|WS_VISIBLE|WS_DISABLED,550,13,140,30,hwnd,(HMENU)IDC_RECOVER,nullptr,nullptr);

        g_list=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|WS_BORDER|LVS_REPORT|LVS_SINGLESEL,16,55,674,330,hwnd,(HMENU)IDC_LIST,nullptr,nullptr);
        ListView_SetExtendedListViewStyle(g_list,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
        LVCOLUMNW c{}; c.mask=LVCF_TEXT|LVCF_WIDTH;
        c.cx=110;c.pszText=(LPWSTR)L"Type";ListView_InsertColumn(g_list,0,&c);
        c.cx=180;c.pszText=(LPWSTR)L"Offset";ListView_InsertColumn(g_list,1,&c);
        c.cx=150;c.pszText=(LPWSTR)L"Size";ListView_InsertColumn(g_list,2,&c);
        c.cx=180;c.pszText=(LPWSTR)L"Confidence";ListView_InsertColumn(g_list,3,&c);

        g_progress=CreateWindowW(PROGRESS_CLASSW,L"",WS_CHILD|WS_VISIBLE,16,395,674,22,hwnd,(HMENU)IDC_PROGRESS,nullptr,nullptr);
        g_status=CreateWindowW(L"STATIC",L"Ready. For best results, run as Administrator and recover to another drive.",WS_CHILD|WS_VISIBLE,16,425,674,40,hwnd,(HMENU)IDC_STATUS,nullptr,nullptr);
        break;
    }
    case WM_COMMAND:
        if (LOWORD(w)==IDC_SCAN) scan(hwnd,false);
        else if (LOWORD(w)==IDC_DEEP) scan(hwnd,true);
        else if (LOWORD(w)==IDC_RECOVER) recoverSelected(hwnd);
        break;
    case WM_APP+1: {
        size_t idx=(size_t)l;
        if (idx<g_files.size()) {
            const auto& f=g_files[idx];
            wchar_t buf[64];
            LVITEMW it{}; it.mask=LVIF_TEXT; it.iItem=(int)idx; it.pszText=(LPWSTR)f.type.c_str(); ListView_InsertItem(g_list,&it);
            swprintf_s(buf, L"0x%llX",(unsigned long long)f.offset); ListView_SetItemText(g_list,(int)idx,1,buf);
            swprintf_s(buf, L"%llu MB",(unsigned long long)(f.size/1048576)); ListView_SetItemText(g_list,(int)idx,2,buf);
            swprintf_s(buf,L"%d%%",f.confidence); ListView_SetItemText(g_list,(int)idx,3,buf);
        }
        EnableWindow(g_recover, TRUE);
        break;
    }
    case WM_APP+2: {
        uint64_t done=(uint64_t)w,total=(uint64_t)l;
        int pct=total? (int)((done*100)/total):0;
        SendMessageW(g_progress,PBM_SETPOS,pct,0);
        wchar_t s[128]; swprintf_s(s,L"Scanning… %d%%  |  %.2f GB / %.2f GB",pct,done/1e9,total/1e9); status(s);
        break;
    }
    case WM_APP+3:
        if (g_worker.joinable()) g_worker.join();
        EnableWindow(g_scan, TRUE); EnableWindow(g_deep, TRUE);
        status(g_cancel ? L"Scan cancelled." : L"Scan finished. Select a result and Recover Selected.");
        break;
    case WM_DESTROY:
        g_cancel=true;
        if (g_worker.joinable()) g_worker.join();
        g_engine.Close();
        PostQuitMessage(0); break;
    }
    return DefWindowProcW(hwnd,msg,w,l);
}

int WINAPI wWinMain(HINSTANCE h, HINSTANCE, PWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX ic{sizeof(ic),ICC_LISTVIEW_CLASSES|ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&ic);
    WNDCLASSW wc{}; wc.hInstance=h; wc.lpfnWndProc=WndProc; wc.lpszClassName=L"RecoverMyFiles"; wc.hCursor=LoadCursor(nullptr,IDC_ARROW);
    RegisterClassW(&wc);
    HWND hwnd=CreateWindowW(wc.lpszClassName,L"Recover My Files — Portable Recovery",WS_OVERLAPPEDWINDOW|WS_VISIBLE,100,100,730,520,nullptr,nullptr,h,nullptr);
    ShowWindow(hwnd,nCmdShow);
    MSG msg{}; while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    return 0;
}
