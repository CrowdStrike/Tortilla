Tortilla v1.0 Beta
by Jason Geffner (jason@crowdstrike.com)
and Cameron Gutman (cameron@crowdstrike.com)

Tortilla is a free and open-source solution for Windows that transparently routes all TCP and DNS traffic through Tor.

This product is produced independently from the Tor(r) anonymity software and carries no guarantee from The Tor Project about quality, suitability or anything else.


LICENSE

Please see the LICENSE.txt file for complete licensing details.  


BUILD INSTRUCTIONS

This distribution comes with a pre-built version of Tortilla.exe. If you would like to use the pre-built Tortilla.exe, you may skip to USAGE INSTRUCTIONS. Otherwise, follow the steps below to build Tortilla.exe with Visual Studio.

Note: Building Tortilla will require WDK 8.0 or higher.

1. Open the Tortilla.sln solution in Visual Studio
2. If you would like to use your own driver signing certificate instead of the test-signed certificate distributed with this distribution, update the Driver Signing Configuration Property in the TortillaAdapter project and the TortillaAdapter Package project
3. In the Visual Studio menu bar, select BUILD -> Batch Build... 
4. In the Batch Build window, check the following items:
    InstallTortillaDriver Debug Win32
    InstallTortillaDriver Debug x64
    InstallTortillaDriver Release Win32
    InstallTortillaDriver Release x64
    Tortilla Debug Win32
    Tortilla Release Win32
    TortillaAdapter Vista Debug Win32
    TortillaAdapter Vista Debug x64
    TortillaAdapter Vista Release Win32
    TortillaAdapter Vista Release x64
    TortillaAdapter Package Vista Debug Win32
    TortillaAdapter Package Vista Debug x64
    TortillaAdapter Package Vista Release Win32
    TortillaAdapter Package Vista Release x64
5. In the Batch Build window, press the Build button

The driver package files, InstallTortillaDriver.exe, and the default Tortilla.ini file all get embedded in Tortilla.exe (created in the \Debug and \Release directories). You need not distribute anything other than Tortilla.exe.


USAGE INSTRUCTIONS

The usage instructions below apply to your host operating system. All of Tortilla's components exist on the host operating system. No Tortilla files need to be copied into your virtual machine.

1. If your host system is Windows Vista or later and the Tortilla driver package is signed with a test-signed certificate, configure your system to support test-signed drivers - http://msdn.microsoft.com/en-us/library/windows/hardware/ff553484(v=vs.85).aspx
2. Download the Tor Expert Bundle from https://www.torproject.org/download (expand the Microsoft Windows drop-down and download the Expert Bundle)
3. Install the Tor Expert Bundle and run Tor
4. Run Tortilla.exe; this will install the Tortilla Adapter as a virtual network adapter and will run the Tortilla client
5. Configure a virtual machine to use the Tortilla Adapter as its network adapter

   For VMware, open Virtual Network Editor, edit or add a new VMnet network, and bridge that VMnet to the Tortilla Adapter. In your virtual machine's Virtual Machine Settings, set the Network Adapter's Network connection to Custom and select the VMnet that was bridged to the Tortilla Adapter.

6. In your virtual machine's guest operating system, ensure that the network adapter's TCP/IPv4 protocol is configured to obtain an IP address automatically via DHCP (Tortilla acts as a simple DHCP server)
7. Use your VM to access the Internet; all TCP and DNS traffic will be automatically and transparently routed through Tor
8. If you like, you may edit the Tortilla.ini file created by Tortilla.exe; restarting Tortilla.exe will cause it to use the configuration in Tortilla.ini


UNINSTALLATION INSTRUCTIONS

1. Delete Tortilla.exe
2. Delete Tortilla.ini
3. Open Device Manager in Windows, expand the list of Network adapters, and delete the Tortilla Adapter


RELEASE NOTES

1.0 Beta
-- Initial release
