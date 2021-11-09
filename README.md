Note before using:
    This library requires that the driver Windows associates with FTDI dongle
    by default should be overriden to use the "libusb-win32" driver.

    The is an application (zadig.exe) that can be used to reassign the drivers
    used by Windows to interface with hardware, this can be downloaded from:
    https://zadig.akeo.ie/

    It is recommended to disconnect devices other than the FTDI dongle in
    question before reassigning Windows drivers to avoid modifying the wrong
    device.

To Install:
    run the setup.py script within this directory from the command prompt with
    the arguement "install"

    i.e.
        C:\\{path_to_python}\python.exe setup.py install

    For help with installation contact Anna Giasson (https://github.com/AnnaGiasson) or
    Ted Kus (https://github.com/TedKus).