This library is useful for communicating with i2C or SMBus or PMBus devices.
The FTDI USB-to-I2C dongle used in the development of this library is is
available at digikey: C232HM-EDHSL-0 or C232HM-DDHSL-0

An example script to read telemetry items in linear11 format is included in the
examples folder: pmbus_tel.py
If you just want to connect to the target i2C device, try setup_example.py for
a minimalist connection example.


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

    For help with installation contact Anna Giasson (https://github.com/AnnaGiasson) or Ted Kus (https://github.com/TedKus).