
"""
Created on 20211109

@author: TedKus

This script uses an FTDI i2c dongle to
1. find a PMBus device by scanning all addresses
2. create an instance of that device called "device" which the user can
communicate with.
Note that additional imports are included but unused, so that this can be copy
pasted to other scripts and the usual suspects are in the lineup.
"""
from useftdi import (get_available_ftdi_urls,  # noqa: F401
                     Use_Ftdi, FtdiError, I2cNackError, PMBus,
                     init_ftdi, find_device)


ftdi_options = {'frequency': int(400000), 'clockstretching': True,
                'initial': 0x78, 'direction': 0x78}
# it's important especially when using GPIO to set them up the way they need
# to be at first.

i2c, gpio = init_ftdi(ftdi_options)
device, i2c_devices = find_device(i2c, PMBus, device=None)
