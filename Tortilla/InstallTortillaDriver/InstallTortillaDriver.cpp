/*!
    @file       InstallTortillaDriver.cpp
    @author     Jason Geffner (jason@crowdstrike.com)
    @brief      Tortilla Driver Installer v1.0 Beta
   
    @details    This product is produced independently from the Tor(r)
                anonymity software and carries no guarantee from The Tor
                Project about quality, suitability or anything else.

                See LICENSE.txt file in top level directory for details.

    @copyright  CrowdStrike, Inc. Copyright (c) 2013.  All rights reserved. 
*/

#include <windows.h>
#include <wchar.h>
#include <devguid.h>
#include <setupapi.h>
#include <newdev.h>
#include <Netcfgx.h>
#include <ShObjIdl.h>
#include "InstallTortillaDriver.h"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "newdev.lib")

/*! 
    @brief Finds the INF-based driver version of an installed device
 
    @param[in] wszDeviceDescription The description of the device
    @param[out] pdwlDriverVersion The driver version number
    @return If the device is found, returns InsTorErrSuccess. If the device is
            not found but no errors occurred, returns InsTorErrDeviceNotFound.
            If errors occurred, returns another INSTALL_TORTILLA_ERROR value.
*/
INSTALL_TORTILLA_ERROR
FindInstalledDevice (
    WCHAR* wszDeviceDescription,
    DWORDLONG* pdwlDriverVersion
    )
{
    INSTALL_TORTILLA_ERROR iteReturn;
    HDEVINFO hDeviceInfoSet;
    DWORD dwIndex;
    BOOL fDeviceFound = FALSE;
    SP_DEVINSTALL_PARAMS DeviceInstallParams;
    SP_DEVINFO_DATA DeviceInfoData;
    BOOL fDriverInfoListBuilt = FALSE;
    SP_DRVINFO_DATA DriverInfoData;

    //
    // Get a handle to the ROOT device information set
    //
    hDeviceInfoSet = SetupDiGetClassDevs(
        &GUID_DEVCLASS_NET,
        L"ROOT",
        NULL,
        0);
    if (hDeviceInfoSet == INVALID_HANDLE_VALUE)
    {
        iteReturn = InsTorErrGetClassDevs;
        goto exit;
    }

    //
    // Enumerate through each device under ROOT
    //
    DeviceInfoData.cbSize = sizeof(DeviceInfoData);
    for (
        dwIndex = 0;
        SetupDiEnumDeviceInfo(
            hDeviceInfoSet,
            dwIndex,
            &DeviceInfoData);
        dwIndex++)
    {
        //
        // Get the current device's description string
        //
        wchar_t wszPropertyBuffer[256] = {0};
        if (!SetupDiGetDeviceRegistryProperty(
            hDeviceInfoSet,
            &DeviceInfoData,
            SPDRP_DEVICEDESC,
            NULL,
            (PBYTE)wszPropertyBuffer,
            sizeof(wszPropertyBuffer),
            NULL))
        {
            continue;
        }

        //
        // Compare the current device's description string to
        // wszDeviceDescription 
        //
        if (0  == wcscmp(wszPropertyBuffer, wszDeviceDescription))
        {
            fDeviceFound = TRUE;
            break;
        }
    }

    //
    // Return InsTorErrDeviceNotFound if the device was not found
    //
    if (!fDeviceFound)
    {
        iteReturn = InsTorErrDeviceNotFound;
        goto exit;
    }

    //
    // When building the list of drivers for this device, only include the
    // currently installed driver, not previous versions of the driver
    //
    DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);
    if (!SetupDiGetDeviceInstallParams(
        hDeviceInfoSet,
        &DeviceInfoData,
        &DeviceInstallParams))
    {
        iteReturn = InsTorErrGetDeviceInstallParams;
        goto exit;
    }
    DeviceInstallParams.FlagsEx = DI_FLAGSEX_INSTALLEDDRIVER;
    if (!SetupDiSetDeviceInstallParams(
        hDeviceInfoSet,
        &DeviceInfoData,
        &DeviceInstallParams))
    {
        iteReturn = InsTorErrSetDeviceInstallParams;
        goto exit;
    }

    //
    // Build the single element "list" of the most recent driver for this
    // device
    //
    if (!SetupDiBuildDriverInfoList(
        hDeviceInfoSet,
        &DeviceInfoData,
        SPDIT_COMPATDRIVER))
    {
        iteReturn = InsTorErrBuildDriverInfoList;
        goto exit;
    }

    fDriverInfoListBuilt = TRUE;

    //
    // Get the device information for the first (and only) element in the
    // driver "list"
    //
    DriverInfoData.cbSize = sizeof(DriverInfoData);
    if (!SetupDiEnumDriverInfo(
        hDeviceInfoSet,
        &DeviceInfoData,
        SPDIT_COMPATDRIVER,
        0,
        &DriverInfoData))
    {
        iteReturn = InsTorErrEnumDriverInfo;
        goto exit;
    }

    //
    // Return the current driver's version number
    //
    *pdwlDriverVersion = DriverInfoData.DriverVersion;
    iteReturn = InsTorErrSuccess;

exit:
    if (fDriverInfoListBuilt)
    {
        SetupDiDestroyDriverInfoList(
            hDeviceInfoSet,
            &DeviceInfoData,
            SPDIT_COMPATDRIVER);
    }
    if (hDeviceInfoSet != INVALID_HANDLE_VALUE)
    {
        SetupDiDestroyDeviceInfoList(hDeviceInfoSet);
    }

    return iteReturn;
}

/*! 
    @brief Unbinds all network bindings for Tortilla Adapater, with the
           exception of the wszEnable list and wszIgnore list
 
    @param[in] wszEnable Space-delimited list of network bindings to enable
                         for Tortilla Adapter
    @param[in] wszIgnore Space-delimited list of network bindings to not
                         modify for Tortilla Adapter
    @return Returns InsTorErrSuccess on success. Returns another
            INSTALL_TORTILLA_ERROR value on error.
*/
INSTALL_TORTILLA_ERROR
UnbindBindings (
    WCHAR* wszEnable,
    WCHAR* wszIgnore
    )
{
    INSTALL_TORTILLA_ERROR iteReturn;
    BOOL fWriteLocked = FALSE;
    BOOL fInitialized = FALSE;

    WCHAR* wszPathToken;
    WCHAR* wszPathArrow;
    WCHAR* wszDup;
    WCHAR* wszContext;
    BOOL fBindingFound;

    INetCfg* pNetCfg = NULL;
    INetCfgLock* pNetCfgLock = NULL;
    INetCfgComponent* pNetCfgComponent = NULL;
    INetCfgComponentBindings* pNetCfgComponentBindings = NULL;
    INetCfgBindingPath* pNetCfgBindingPath = NULL;
    IEnumNetCfgBindingPath* pEnumNetCfgBindingPath = NULL;

    HRESULT hr;

    //
    // Initialize the COM library
    //
    if (S_OK != CoInitialize(
        NULL))
    {
        iteReturn = InsTorErrCoInitialize;
        goto exit;
    }

    //
    // Create a networking configuration and installation object
    //
    if (S_OK != CoCreateInstance(
        CLSID_CNetCfg,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_INetCfg,
        (PVOID*)&pNetCfg))
    {
        iteReturn = InsTorErrCoCreateInstance;
        goto exit;
    }

    //
    // Acquire a write-lock on the object
    //
    if (S_OK != pNetCfg->QueryInterface(
        IID_INetCfgLock,
        (PVOID*)&pNetCfgLock))
    {
        iteReturn = InsTorErrQueryNetCfgLock;
        goto exit;
    }
    if (S_OK != pNetCfgLock->AcquireWriteLock(
        5000,   
        L"InstallTortillaDriver",
        NULL))
    {
        iteReturn = InsTorErrAcquireWriteLock;
        goto exit;
    }

    fWriteLocked = TRUE;

    //
    // Initialize the network configuration
    //
    if (S_OK != pNetCfg->Initialize(
        NULL))
    {
        iteReturn = InsTorErrInitialize;
        goto exit;
    }

    fInitialized = TRUE;
    
    //
    // Find the Tortilla Adapter
    //
    if (S_OK != pNetCfg->FindComponent(
        L"*tortilla",
        &pNetCfgComponent))
    {
        iteReturn = InsTorErrFindComponent;
        goto exit;
    }

    //
    // Get list of network component bindings for Tortilla Adapter
    //
    if (S_OK != pNetCfgComponent->QueryInterface(
        IID_INetCfgComponentBindings,
        (PVOID*)&pNetCfgComponentBindings))
    {
        iteReturn = InsTorErrQueryNetCfgComponentBindings;
        goto exit;
    }
    if (S_OK != pNetCfgComponentBindings->EnumBindingPaths(
        EBP_ABOVE,
        &pEnumNetCfgBindingPath))
    {
        iteReturn = InsTorErrEnumBindingPaths;
        goto exit;
    }

    iteReturn = InsTorErrSuccess;

    //
    // Enumerate through each network component binding for Tortilla Adapter
    //
    while (S_OK == pEnumNetCfgBindingPath->Next(
            1,
            &pNetCfgBindingPath,
            NULL))
    {
        if (S_OK != pNetCfgBindingPath->GetPathToken(
            &wszPathToken))
        {
            iteReturn = InsTorErrGetPathToken;
            goto exit;
        }

        //
        // Terminate the path token at the first "->"
        //
        wszPathArrow = wcsstr(
            wszPathToken,
            L"->");
        if (wszPathArrow != NULL)
        {
            *wszPathArrow = 0;
        }

        fBindingFound = FALSE;

        //
        // Search the wszEnable list for this network component binding
        //
        wszDup = _wcsdup(wszEnable);
        if (NULL == wszDup)
        {
            iteReturn = InsTorErrStringDup;
            goto exit;
        }
        for (
            wchar_t* wszBinding = wcstok_s(wszDup, L" \t", &wszContext);
            wszBinding != NULL;
            wszBinding = wcstok_s(NULL, L" \t", &wszContext))
        {
            if (0 == wcsncmp(
                wszPathToken,
                wszBinding,
                wcslen(wszBinding)))
            {
                //
                // We found a wszEnable binding, so enable it
                //
                fBindingFound = TRUE;

                if (S_OK != pNetCfgBindingPath->Enable(
                    TRUE))
                {
                    iteReturn = InsTorErrBindingEnable;
                }
                    
                break;
            }
        }
        free(wszDup);

        //
        // Continue to the next network component binding if the current one
        // was just bound
        //
        if (fBindingFound)
        {
            goto next;
        }

        //
        // Search the wszIgnore list for this network component binding
        //
        wszDup = _wcsdup(wszIgnore);
        if (NULL == wszDup)
        {
            iteReturn = InsTorErrStringDup;
            goto exit;
        }
        for (
            wchar_t* wszBinding = wcstok_s(wszDup, L" \t", &wszContext);
            wszBinding != NULL;
            wszBinding = wcstok_s(NULL, L" \t", &wszContext))
        {
            if (0 == wcsncmp(
                wszPathToken,
                wszBinding,
                wcslen(wszBinding)))
            {
                //
                // We found a wszIgnore binding, so don't modify it
                //
                fBindingFound = TRUE;

                break;
            }
        }
        free(wszDup);

        //
        // Continue to the next network component binding if the current one
        // was in the wszIgnore list
        //
        if (fBindingFound)
        {
            goto next;
        }

        //
        // The current network component binding was not in the wszEnable list
        // or wszIgnore list, so disable it by default
        //
        if (S_OK != pNetCfgBindingPath->Enable(
            FALSE))
        {
            iteReturn = InsTorErrBindingDisable;
        }

        HRESULT hrEnabled = pNetCfgBindingPath->IsEnabled();

next:
        CoTaskMemFree(
            wszPathToken);

        pNetCfgBindingPath->Release();

        if ((iteReturn == InsTorErrBindingEnable) ||
            (iteReturn == InsTorErrBindingDisable))
        {
            goto exit;
        }
    }

    hr = pNetCfg->Apply();
    if (hr == NETCFG_S_REBOOT)
    {
        iteReturn = InsTorErrRebootRequired;
        goto exit;
    }
    else if (hr != S_OK)
    {
        iteReturn = InsTorErrApply;
        goto exit;
    }

exit:
    if (pEnumNetCfgBindingPath != NULL)
    {
        pEnumNetCfgBindingPath->Release();
    }
    if (pNetCfgComponentBindings != NULL)
    {
        pNetCfgComponentBindings->Release();
    }
    if (pNetCfgComponent != NULL)
    {
        pNetCfgComponent->Release();
    }
    if (fInitialized)
    {
        pNetCfg->Uninitialize();
    }
    if (fWriteLocked)
    {
        pNetCfgLock->ReleaseWriteLock();
    }
    if (pNetCfgLock != NULL)
    {
        pNetCfgLock->Release();
    }
    if (pNetCfg != NULL)
    {
        pNetCfg->Release();
    }
    CoUninitialize();

    return iteReturn;
}

/*! 
    @brief Installs/updates Tortilla driver as necessary and unbinds Tortilla
           Adapter's network bindings
 
    @param[in] argc Number of arguments passed to program from command line.
                    Must be the value 3.
    @param[in] argv Array of arguments from command line. argv[0] is file name
                    of this program. argv[1] is space-delimited list of
                    network bindings to enable for Tortilla Adapter. argv[2]
                    is space-delimited list of network bindings to not modify
                    for Tortilla Adapter.
    @return Returns InsTorErrSuccess on success. Returns another
            INSTALL_TORTILLA_ERROR value on failure.
*/
INT
wmain (
    INT argc,
    WCHAR* argv[]
    )
{
    INSTALL_TORTILLA_ERROR iteReturn;
    WCHAR wszInfPath[MAX_PATH];
    DWORDLONG dwlDriverVersion;
    WCHAR wszBundledDriverVer[32];
    WCHAR wszInstalledDriverVer[32];
    BOOL fRebootRequired;
    HDEVINFO hDeviceInfoSet;
    SP_DEVINFO_DATA DeviceInfoData;
    HKEY hDevRegKey = (HKEY)INVALID_HANDLE_VALUE;
    WCHAR wszNetCfgInstanceId[39];
    DWORD cbData;
    BOOL fCoInitialized = FALSE;
    IShellFolder2* pShellFolder2 = NULL;
    PIDLIST_RELATIVE pIdl = NULL;

    //
    // Validate the number of command line arguments
    //
    if (argc != 3)
    {
        iteReturn = InsTorErrCommandLine;
        goto exit;
    }
    
    //
    // Get the file path for the extracted netTor.inf file
    //
    if (0 == GetTempPath(
        _countof(wszInfPath),
        wszInfPath))
    {
        iteReturn = InsTorErrInfPath;
        goto exit;
    }
    if (0 != wcscat_s(
        wszInfPath,
        _countof(wszInfPath),
        L"netTor.inf"))
    {
        iteReturn = InsTorErrInfPath;
        goto exit;
    }

    iteReturn = FindInstalledDevice(
        L"Tortilla Adapter",
        &dwlDriverVersion);

    if (iteReturn == InsTorErrSuccess)
    {
        //
        // The Tortilla Adapter driver is already installed. Let's make sure
        // it's the same version as the bundled driver, and if not, update it.
        //
        
        //
        // Get the bundled driver's version number from the extracted
        // netTor.inf
        //
        if (0 == GetPrivateProfileString(
            L"Version",
            L"DriverVer",
            NULL,
            wszBundledDriverVer,
            _countof(wszBundledDriverVer),
            wszInfPath))
        {
            iteReturn = InsTorErrInfRead;
            goto exit;
        }

        //
        // Compare the installed driver's version number to the bundled
        // driver's version number
        //
        if (-1 == swprintf_s(
            wszInstalledDriverVer,
            L",%d.%d.%d.%d",
            (WORD)((dwlDriverVersion >> 0x30) & 0xFFFF),
            (WORD)((dwlDriverVersion >> 0x20) & 0xFFFF),
            (WORD)((dwlDriverVersion >> 0x10) & 0xFFFF),
            (WORD)((dwlDriverVersion >> 0x00) & 0xFFFF)))
        {
            iteReturn = InsTorErrPrintVer;
            goto exit;
        }
        if (0 == wcsncmp(
            _wcsrev(wszBundledDriverVer),
            _wcsrev(wszInstalledDriverVer),
            wcslen(wszInstalledDriverVer)))
        {
            //
            // The version numbers are the same, so return InsTorErrSuccess
            //
            goto exit;
        }

        //
        // The bundled driver is different from the installed one, so replace
        // the installed driver with the bundled one
        //
        if (!UpdateDriverForPlugAndPlayDevices(
            NULL,
            L"*tortilla",
            wszInfPath,
            INSTALLFLAG_FORCE,
            &fRebootRequired))
        {
            iteReturn = InsTorErrUpdateDriver;
            goto exit;
        }
        if (fRebootRequired)
        {
            iteReturn = InsTorErrRebootRequired;
        }
    }
    else if (iteReturn == InsTorErrDeviceNotFound)
    {
        //
        // The driver is not already installed so install it now
        //
        
        //
        // Create a new device information set
        //
        hDeviceInfoSet = SetupDiCreateDeviceInfoList(
            &GUID_DEVCLASS_NET,
            NULL);
        if (hDeviceInfoSet == INVALID_HANDLE_VALUE)
        {
            iteReturn = InsTorErrCreateDeviceInfoList;
            goto exitNewDriverInstall;
        }

        //
        // Create a new device information element
        //
        DeviceInfoData.cbSize = sizeof(DeviceInfoData);
        if (!SetupDiCreateDeviceInfo(
            hDeviceInfoSet,
            L"Net",
            &GUID_DEVCLASS_NET,
            NULL,
            NULL,
            DICD_GENERATE_ID,
            &DeviceInfoData))
        {
            iteReturn = InsTorErrCreateDeviceInfo;
            goto exitNewDriverInstall;
        }

        //
        // Set the new device's hardware ID
        //
        if (!SetupDiSetDeviceRegistryProperty(
            hDeviceInfoSet,
            &DeviceInfoData,
            SPDRP_HARDWAREID,
            (BYTE*)L"*tortilla\x00\x00",
            (DWORD)(wcslen(L"*tortilla\x00\x00") + 1 + 1) * sizeof(wchar_t)))
        {
            iteReturn = InsTorErrSetDeviceRegistryProperty;
            goto exitNewDriverInstall;
        }

        //
        // Register the new device
        //
        if (!SetupDiCallClassInstaller(
            DIF_REGISTERDEVICE,
            hDeviceInfoSet,
            &DeviceInfoData))
        {
            iteReturn = InsTorErrCallClassInstaller;
            goto exitNewDriverInstall;
        }

        //
        // Install the device driver
        //
        if (!UpdateDriverForPlugAndPlayDevices(
            NULL,
            L"*tortilla",
            wszInfPath,
            INSTALLFLAG_FORCE,
            &fRebootRequired))
        {
            iteReturn = InsTorErrInstallDriver;
            goto exitNewDriverInstall;
        }
        iteReturn = fRebootRequired ? InsTorErrRebootRequired :
            InsTorErrSuccess;

        //
        // The code below tries to set the name of the Tortilla Adapapter in
        // the Network Connections folder (changing it from "Ethernet #" to
        // "Tortilla Adapter"). This change is purely cosmetic, so don't return
        // an error if there's a failure below.
        //

        //
        // Get the Instance ID GUID for the Tortilla Adapter device
        //
        hDevRegKey = SetupDiOpenDevRegKey(
            hDeviceInfoSet,
            &DeviceInfoData,
            DICS_FLAG_GLOBAL,
            0,
            DIREG_DRV,
            KEY_READ);
        if (hDevRegKey == INVALID_HANDLE_VALUE)
        {
            goto exitNewDriverInstall;
        }
        cbData = sizeof(wszNetCfgInstanceId);
        if (ERROR_SUCCESS != RegQueryValueEx(
            hDevRegKey,
            L"NetCfgInstanceId",
            NULL,
            NULL,
            (BYTE*)wszNetCfgInstanceId,
            &cbData))
        {
            goto exitNewDriverInstall;
        }

        //
        // Initialize the COM library
        //
        if (S_OK != CoInitialize(
            NULL))
        {
            goto exitNewDriverInstall;
        }
        fCoInitialized = TRUE;

        //
        // Create an instance of the Network Connections shell folder object
        //
        if (S_OK != CoCreateInstance(
            CLSID_NetworkConnections,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IShellFolder2,
            (VOID**)&pShellFolder2))
        {
            goto exitNewDriverInstall;
        }

        //
        // Convert the Instance ID GUID for the Tortilla Adapter device to an
        // item identifier list
        //
        if (S_OK != pShellFolder2->ParseDisplayName(
            NULL,
            NULL,
            wszNetCfgInstanceId,
            NULL,
            &pIdl,
            NULL))
        {
            goto exitNewDriverInstall;
        }

        //
        // Change the name of the Tortilla Adapter in the Network Connections
        // shell folder to "Tortilla Adapter"
        //
        if (S_OK != pShellFolder2->SetNameOf(
            NULL,
            pIdl,
            L"Tortilla Adapter",
            SHGDN_NORMAL,
            &pIdl))
        {
            goto exitNewDriverInstall;
        }

exitNewDriverInstall:
        if (pIdl != NULL)
        {
            CoTaskMemFree(pIdl);
        }
        if (pShellFolder2 != NULL)
        {
            pShellFolder2->Release();
        }
        if (fCoInitialized)
        {
            CoUninitialize();
        }
        if (hDevRegKey != INVALID_HANDLE_VALUE)
        {
            RegCloseKey(hDevRegKey);
        }
        if (hDeviceInfoSet != INVALID_HANDLE_VALUE)
        {
            SetupDiDestroyDeviceInfoList(hDeviceInfoSet);
        }
    }

exit:
    if (iteReturn != InsTorErrSuccess)
    {
        return iteReturn;
    }

    //
    // Unbind all Tortilla Adapter network bindings except for the bindings
    // specified on the command-line
    //
    return UnbindBindings(
        argv[1],
        argv[2]);
}

