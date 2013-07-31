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