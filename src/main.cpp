#include "recovery_engine.h"
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <atomic>
#include <thread>
#include <vector>
#include <string>
#include <cwctype>
#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"ole32.lib")

static HWND listBox,statusBox,progressBar,scanBtn,deepBtn,recoverBtn,sourceBox;
static RecoveryEngine engine;
static std::vector<RecoveryFile> results;
static std::atomic_bool cancelScan{false};
static std::thread worker;
enum {SRC=1001,SCAN=1002,DEEP=1003,RESULTS=1004,RECOVER=1005};

static void Status(const std::wstring&s){SetWindowTextW(statusBox,s.c_str());}
static void Add(HWND c,const std::wstring&s){SendMessageW(c,CB_ADDSTRING,0,(LPARAM)s.c_str());}
static void Sources(HWND c){
 wchar_t d[512]{}; GetLogicalDriveStringsW(511,d);
 for(wchar_t*p=d;*p;p+=wcslen(p)+1) Add(c,L"\\.\"+std::wstring(p,2));
 for(int i=0;i<32;i++){std::wstring x=L"\\\\.\\PhysicalDrive"+std::to_wstring(i);HANDLE h=CreateFileW(x.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);if(h!=INVALID_HANDLE_VALUE){Add(c,x);CloseHandle(h);}}
}
static bool IsVolume(const std::wstring&s){return s.size()>=6 && s.rfind(L"\\\\.\\",0)==0 && s.find(L"PhysicalDrive")==std::wstring::npos;}
static void Start(HWND w,bool deep){
 if(worker.joinable())return;
 wchar_t src[128]{};GetWindowTextW(sourceBox,src,128);std::wstring selected(src),err;
 bool opened=IsVolume(selected)?engine.OpenVolume(selected,err):engine.OpenPhysicalDrive(selected,err);
 if(!opened){Status(err);return;}
 results.clear();ListView_DeleteAllItems(listBox);cancelScan=false;
 EnableWindow(scanBtn,FALSE);EnableWindow(deepBtn,FALSE);EnableWindow(recoverBtn,FALSE);
 Status(deep?L"Deep Scan: raw signature carving...":L"Quick Scan: NTFS MFT metadata scan...");
 worker=std::thread([w,deep](){std::wstring e;bool ok=engine.Scan(deep,cancelScan,[w](const ScanStats&s,const RecoveryFile*f){
   if(f){results.push_back(*f);PostMessageW(w,WM_APP+1,0,(LPARAM)(results.size()-1));}
   PostMessageW(w,WM_APP+2,(WPARAM)s.bytesRead,(LPARAM)s.totalBytes);
 },e);PostMessageW(w,WM_APP+3,ok,0);});
}
static void Recover(HWND w){
 int i=ListView_GetNextItem(listBox,-1,LVNI_SELECTED);
 if(i<0||i>=(int)results.size()){Status(L"Select a recovered file.");return;}
 BROWSEINFOW b{};b.hwndOwner=w;b.lpszTitle=L"Choose recovery destination on another drive";
 PIDLIST_ABSOLUTE p=SHBrowseForFolderW(&b);if(!p)return;
 wchar_t path[MAX_PATH]{};SHGetPathFromIDListW(p,path);CoTaskMemFree(p);if(!*path)return;
 wchar_t root[4]{};if(GetVolumePathNameW(path,root,4) && IsVolume(engine.Source())){
   std::wstring s=engine.Source();
   if(s.size()>=6 && _wcsnicmp(s.c_str()+4,root,3)==0){Status(L"Safety stop: destination is the source drive.");return;}
 }
 std::wstring e;if(engine.Recover(results[i],path,e))Status(L"Recovery completed. Source was read-only.");else Status(e);
}
LRESULT CALLBACK Proc(HWND w,UINT msg,WPARAM a,LPARAM b){
 switch(msg){
 case WM_CREATE:{
  CreateWindowW(L"STATIC",L"Source:",WS_CHILD|WS_VISIBLE,15,15,60,25,w,nullptr,nullptr,nullptr);
  sourceBox=CreateWindowW(L"COMBOBOX",L"",WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST,75,12,430,260,w,(HMENU)SRC,nullptr,nullptr);Sources(sourceBox);SendMessageW(sourceBox,CB_SETCURSEL,0,0);
  scanBtn=CreateWindowW(L"BUTTON",L"Quick Scan",WS_CHILD|WS_VISIBLE,515,12,95,30,w,(HMENU)SCAN,nullptr,nullptr);
  deepBtn=CreateWindowW(L"BUTTON",L"Deep Scan",WS_CHILD|WS_VISIBLE,615,12,95,30,w,(HMENU)DEEP,nullptr,nullptr);
  recoverBtn=CreateWindowW(L"BUTTON",L"Recover",WS_CHILD|WS_VISIBLE|WS_DISABLED,715,12,95,30,w,(HMENU)RECOVER,nullptr,nullptr);
  listBox=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|WS_BORDER|LVS_REPORT|LVS_SINGLESEL,15,55,795,330,w,(HMENU)RESULTS,nullptr,nullptr);
  ListView_SetExtendedListViewStyle(listBox,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
  LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH;c.cx=75;c.pszText=(LPWSTR)L"Type";ListView_InsertColumn(listBox,0,&c);
  c.cx=360;c.pszText=(LPWSTR)L"Recovered path";ListView_InsertColumn(listBox,1,&c);
  c.cx=170;c.pszText=(LPWSTR)L"Size";ListView_InsertColumn(listBox,2,&c);
  c.cx=90;c.pszText=(LPWSTR)L"Confidence";ListView_InsertColumn(listBox,3,&c);
  progressBar=CreateWindowW(PROGRESS_CLASSW,L"",WS_CHILD|WS_VISIBLE,15,395,795,22,w,nullptr,nullptr,nullptr);
  statusBox=CreateWindowW(L"STATIC",L"Ready. Run as Administrator. Never recover onto the source disk.",WS_CHILD|WS_VISIBLE,15,425,795,40,w,nullptr,nullptr,nullptr);
  break;}
 case WM_COMMAND:
  if(LOWORD(a)==SCAN)Start(w,false);else if(LOWORD(a)==DEEP)Start(w,true);else if(LOWORD(a)==RECOVER)Recover(w);break;
 case WM_APP+1:{
  size_t i=(size_t)b;if(i<results.size()){auto&f=results[i];LVITEMW x{};x.mask=LVIF_TEXT;x.iItem=(int)i;x.pszText=(LPWSTR)f.type.c_str();ListView_InsertItem(listBox,&x);
   ListView_SetItemText(listBox,(int)i,1,(LPWSTR)f.path.c_str());wchar_t z[96];
   if(f.size>=1024ULL*1024*1024)swprintf_s(z,L"%.2f GB",f.size/1073741824.0);else swprintf_s(z,L"%.2f MB",f.size/1048576.0);
   ListView_SetItemText(listBox,(int)i,2,z);swprintf_s(z,L"%d%%",f.confidence);ListView_SetItemText(listBox,(int)i,3,z);}
  EnableWindow(recoverBtn,TRUE);break;}
 case WM_APP+2:{
  uint64_t d=(uint64_t)a,t=(uint64_t)b;SendMessageW(progressBar,PBM_SETPOS,t?(d*100/t):0,0);wchar_t z[200];
  swprintf_s(z,L"Scanning: %llu / %llu MB | candidates: %zu",d/1048576,t/1048576,results.size());Status(z);break;}
 case WM_APP+3:
  if(worker.joinable())worker.join();EnableWindow(scanBtn,TRUE);EnableWindow(deepBtn,TRUE);Status(L"Scan finished. Select a result and Recover.");break;
 case WM_DESTROY:cancelScan=true;if(worker.joinable())worker.join();engine.Close();PostQuitMessage(0);break;
 }
 return DefWindowProcW(w,msg,a,b);
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE, PWSTR,int n){
 INITCOMMONCONTROLSEX ic{sizeof(ic),ICC_LISTVIEW_CLASSES|ICC_PROGRESS_CLASS};InitCommonControlsEx(&ic);
 WNDCLASSW c{};c.hInstance=h;c.lpfnWndProc=Proc;c.lpszClassName=L"RecoverMyFiles";c.hCursor=LoadCursor(nullptr,IDC_ARROW);RegisterClassW(&c);
 HWND w=CreateWindowW(c.lpszClassName,L"Recover My Files - Portable Recovery",WS_OVERLAPPEDWINDOW|WS_VISIBLE,80,80,850,520,nullptr,nullptr,h,nullptr);
 ShowWindow(w,n);MSG m{};while(GetMessageW(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}return 0;
}
