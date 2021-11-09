
"""
Created on 20211109

@author: TedKus

This script uses an FTDI i2c dongle to
1. find a PMBus device
2. ask an output file name for telemetry
3. ask if telemetry should be printed to the screen
4. ask delay time (default 0) between readings
5. ask to start reading telemetry
6. reads telemetry from all channels of the device and writes to output file
"""
from useftdi import (get_available_ftdi_urls,  # noqa: F401
                     Use_Ftdi, FtdiError, I2cNackError, PMBus,
                     init_ftdi, find_device)
import time
from datetime import datetime


ftdi_options = {'frequency': int(400000), 'clockstretching': True,
                'initial': 0x78, 'direction': 0x78}
# it's important especially when using GPIO to set them up the way they need
# to be at first.


def user_query(query: str = 'save?', entry: list = ['y', 'n']):
    """
    user_query(query, choices)

    Args:
        query (str, optional): [promt the user with this]. Defaults to 'save?'.
        choices (list, optional): [what do they type for yay/nay]. Defaults
        to ['y','n'].

    Returns:
        [bool]: pick, True/False for entry[0,1] respectively
        [bool]: stop, True indicates the user typed 'exit'
    """

    while True:
        user_save = input(f"{query} {entry[0]}/{entry[1]}: ").lower()

        if user_save == entry[0]:
            pick, stop = (True, False)

        elif user_save == entry[1]:
            pick, stop = (False, False)

        elif user_save == "exit":
            pick, stop = (False, True)

        else:
            print(f"only type {entry[0]} or {entry[1]}."
                  "You can exit by typing 'exit'")
            continue
        break

    return (pick, stop)


def get_tel(device, return_data: bool = False):
    query = "Telemetry Filename"

    verbose, stop = user_query(query="print telemetry to screen? y/n: ")

    query = "Telemetry Delay Time? 0.1 for default"
    read_delay = float(input(f"{query}: ") or "0.1")

    vin_array = []
    iin_array = []
    vout_array = []
    iout_array = []
    temp1_array = []
    pout_array = []
    pin_array = []
    vout_command_array = []
    status_array = []
    status_word_array = []
    status_vout_array = []
    status_iout_array = []
    status_input_array = []
    status_temperature_array = []
    status_cml_array = []
    status_other_array = []
    status_mfr_specific_array = []
    time_array = []

    go, stop = user_query(query="Read Telemetry Now? Type exit to stop: ")
    try:
        print("type Ctrl+C to stop")
        while go:

            try:
                read_vin = device.decode_lin11(device.read_vin())
                read_iin = device.decode_lin11(device.read_iin())
                read_vout = device.decode_lin11(device.read_vout())
                read_iout = device.decode_lin11(device.read_iout())
                read_temp1 = device.decode_lin11(device.read_temperature_1())
                read_pout = device.decode_lin11(device.read_pout())
                read_pin = device.decode_lin11(device.read_pin())
                read_vout_command = device.decode_ulin16(device.get_vout_command())  # noqa: E501
                read_status = device.status_byte(bits=True)  # noqa: E501
                read_status_word = device.status_word(bits=True)  # noqa: E501
                read_status_vout = device.status_vout(bits=True)  # noqa: E501
                read_status_iout = device.status_iout(bits=True)  # noqa: E501
                read_status_input = device.status_input(bits=True)  # noqa: E501
                read_status_temperature = device.status_temperature(bits=True)  # noqa: E501
                read_status_cml = device.status_cml(bits=True)  # noqa: E501
                read_status_other = device.status_other(bits=True)  # noqa: E501
                read_status_mfr_specific = device.status_mfr_specific(bits=True)  # noqa: E501
                time_done = datetime.now()

                if verbose:
                    print(f'read_vin={read_vin :.4f}, '
                          f'read_iin={read_iin :.4f}, '
                          f'read_vout={read_vout :.4f}, '
                          f'read_iout={read_iout :.4f}, '
                          f'read_temp1={read_temp1 :.4f}, '
                          f'read_pout={read_pout :.4f}, '
                          f'read_pin={read_pin :.4f}, '
                          f'read_vout_command={read_vout_command :.4f}, '
                          # f'read_status={read_status}, '
                          # f'read_status_word={read_status_word}, '
                          f'datetime={time_done}')

                vin_array.append(read_vin)
                iin_array.append(read_iin)
                vout_array.append(read_vout)
                iout_array.append(read_iout)
                temp1_array.append(read_temp1)
                pout_array.append(read_pout)
                pin_array.append(read_pin)
                vout_command_array.append(read_vout_command)
                status_array.append(read_status)
                status_word_array.append(read_status_word)
                status_vout_array.append(read_status_vout)
                status_iout_array.append(read_status_iout)
                status_input_array.append(read_status_input)
                status_temperature_array.append(read_status_temperature)
                status_cml_array.append(read_status_cml)
                status_other_array.append(read_status_other)
                status_mfr_specific_array.append(read_status_mfr_specific)
                time_array.append(time_done)

            except I2cNackError:
                print('Nack occured')

            time.sleep(read_delay)
            # need to make a function to append to a json output-
    except KeyboardInterrupt:
        device.get_page(relax=True)  # relax the i2c clock
        pass

    if return_data:
        return (vin_array, iin_array, vout_array, iout_array, temp1_array,
                pout_array, pin_array, time_array, vout_command_array,
                status_array,
                status_word_array,
                status_vout_array,
                status_iout_array,
                status_input_array,
                status_temperature_array,
                status_cml_array,
                status_other_array,
                status_mfr_specific_array)
    return None


i2c, gpio = init_ftdi(ftdi_options)
device, i2c_devices = find_device(i2c, PMBus, device=None)

print('type get_tel(device) to run telemetry')
print(('a more advanced output type: '
       'vin_array, iin_array, vout_array, '
       'iout_array, temp1_array, pout_array'
       ',pin_array, time_array, vout_command_array, status_array,'
       'status_word_array,'
       'status_vout_array,'
       'status_iout_array,'
       'status_input_array,'
       'status_temperature_array,'
       'status_cml_array,'
       'status_other_array,'
       'status_mfr_specific_array = get_tel(device, return_data=True)   '
       'to run telemetry'
       ' and to return the data collected for further use'))
# get_tel()
