/*!
    @file       InstallTortillaDriver.cpp
    @author     Jason Geffner (jason@crowdstrike.com)
    @brief      Tortilla Driver Installer v1.1.0 Beta
   
    @details    This product is produced independently from the Tor(r)
                anonymity software and carries no guarantee from The Tor
                Project about quality, suitability or anything else.

                See LICENSE.txt file in top level directory for details.

    @copyright  CrowdStrike, Inc. Copyright (c) 2013.  All rights reserved. 
*/

typedef enum _INSTALL_TORTILLA_ERROR
{
    InsTorErrSuccess,

    //
    // wmain()
    //
    InsTorErrCommandLine,
    InsTorErrInfPath,
    InsTorErrInfRead,
    InsTorErrPrintVer,
    InsTorErrUpdateDriver,
    InsTorErrRebootRequired,
    InsTorErrCreateDeviceInfoList,
    InsTorErrCreateDeviceInfo,
    InsTorErrSetDeviceRegistryProperty,
    InsTorErrCallClassInstaller,
    InsTorErrInstallDriver,

    //
    // FindInstalledDevice()
    //
    InsTorErrGetClassDevs,
    InsTorErrDeviceNotFound,
    InsTorErrGetDeviceInstallParams,
    InsTorErrSetDeviceInstallParams,
    InsTorErrBuildDriverInfoList,
    InsTorErrEnumDriverInfo,

    //
    // UnbindBindings()
    //
    InsTorErrCoInitialize,
    InsTorErrCoCreateInstance,
    InsTorErrQueryNetCfgLock,
    InsTorErrAcquireWriteLock,
    InsTorErrInitialize,
    InsTorErrFindComponent,
    InsTorErrQueryNetCfgComponentBindings,
    InsTorErrEnumBindingPaths,
    InsTorErrGetPathToken,
    InsTorErrStringDup,
    InsTorErrBindingEnable,
    InsTorErrBindingDisable,
    InsTorErrApply
} INSTALL_TORTILLA_ERROR;