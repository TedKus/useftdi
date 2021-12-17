from .useftdi_core import Use_Ftdi, toNametuple

# created by Ted Kus, contact tkus@vicr.com for support or issues
# query_slave etc should have a PEC option to do PEC automatically.
# block_write and block_read can be modified to accept the n_bytes and to
# automatically write or read that many more bytes by setting start = True
# and relax = False on the first write/read and then adding another
# write/read of n_bytes with start=False.  This would be more robust
# and universal than the hard-coded methods below.
# getting the PEC byte can use the same trick, set relax!=usepec and
# then if usepec: read_slave(...)


class PMBus(Use_Ftdi):
    """
    PMBus has methods to fetch all pmbus commands
    PMBus.commands is a named tuple of pmbus commands
    Note that the commands to set various parameters do not read the slave to
    check that the command was accepted. Each command does the minimum
    deterministic function.
    """

    pmbus_dict = {'page': 0x00, 'operation': 0x01, 'on_off_config': 0x02, 'clear_faults': 0x03, 'phase': 0x04, 'page_plus_write': 0x05, 'page_plus_read': 0x06, 'zone_config': 0x07, 'zone_active': 0x08, 'reserved_09': 0x09, 'reserved_0a': 0x0a, 'reserved_0b': 0x0b, 'reserved_0c': 0x0c, 'reserved_0d': 0x0d, 'reserved_0e': 0x0e, 'reserved_0f': 0x0f, 'write_protect': 0x10, 'store_default_all': 0x11, 'restore_default_all': 0x12, 'store_default_code': 0x13, 'restore_default_code': 0x14, 'store_user_all': 0x15, 'restore_user_all': 0x16, 'store_user_code': 0x17, 'restore_user_code': 0x18, 'capability': 0x19, 'query': 0x1a, 'smbalert_mask': 0x1b, 'reserved_1c': 0x1c, 'reserved_1d': 0x1d, 'reserved_1e': 0x1e, 'reserved_1f': 0x1f, 'vout_mode': 0x20, 'vout_command': 0x21, 'vout_trim': 0x22, 'vout_cal_offset': 0x23, 'vout_max': 0x24, 'vout_margin_high': 0x25, 'vout_margin_low': 0x26, 'vout_transition_rate': 0x27, 'vout_droop': 0x28, 'vout_scale_loop': 0x29, 'vout_scale_monitor': 0x2a, 'vout_min': 0x2b, 'reserved_2c': 0x2c, 'reserved_2d': 0x2d, 'reserved_2e': 0x2e, 'reserved_2f': 0x2f, 'coefficients': 0x30, 'pout_max': 0x31, 'max_duty': 0x32, 'frequency_switch': 0x33, 'power_mode': 0x34, 'vin_on': 0x35, 'vin_off': 0x36, 'interleave': 0x37, 'iout_cal_gain': 0x38, 'iout_cal_offset': 0x39, 'fan_config_1_2': 0x3a, 'fan_command_1': 0x3b, 'fan_command_2': 0x3c, 'fan_config_3_4': 0x3d, 'fan_command_3': 0x3e, 'fan_command_4': 0x3f, 'vout_ov_fault_limit': 0x40, 'vout_ov_fault_response': 0x41, 'vout_ov_warn_limit': 0x42, 'vout_uv_warn_limit': 0x43, 'vout_uv_fault_limit': 0x44, 'vout_uv_fault_response': 0x45, 'iout_oc_fault_limit': 0x46, 'iout_oc_fault_response': 0x47, 'iout_oc_lv_fault_limit': 0x48, 'iout_oc_lv_fault_response': 0x49, 'iout_oc_warn_limit': 0x4a, 'iout_uc_fault_limit': 0x4b, 'iout_uc_fault_response': 0x4c, 'reserved_4d': 0x4d, 'reserved_4e': 0x4e, 'ot_fault_limit': 0x4f, 'ot_fault_response': 0x50, 'ot_warn_limit': 0x51, 'ut_warn_limit': 0x52, 'ut_fault_limit': 0x53, 'ut_fault_response': 0x54, 'vin_ov_fault_limit': 0x55, 'vin_ov_fault_response': 0x56, 'vin_ov_warn_limit': 0x57, 'vin_uv_warn_limit': 0x58, 'vin_uv_fault_limit': 0x59, 'vin_uv_fault_response': 0x5a, 'iin_oc_fault_limit': 0x5b, 'iin_oc_fault_response': 0x5c, 'iin_oc_warn_limit': 0x5d, 'power_good_on': 0x5e, 'power_good_off': 0x5f, 'ton_delay': 0x60, 'ton_rise': 0x61, 'ton_max_fault_limit': 0x62, 'ton_max_fault_response': 0x63, 'toff_delay': 0x64, 'toff_fall': 0x65, 'toff_max_warn_limit': 0x66, 'reserved_67': 0x67, 'pout_op_fault_limit': 0x68, 'pout_op_fault_response': 0x69, 'pout_op_warn_limit': 0x6a, 'pin_op_warn_limit': 0x6b, 'reserved_6c': 0x6c, 'reserved_6d': 0x6d, 'reserved_6e': 0x6e, 'reserved_6f': 0x6f, 'reserved_70': 0x70, 'reserved_71': 0x71, 'reserved_72': 0x72, 'reserved_73': 0x73, 'reserved_74': 0x74, 'reserved_75': 0x75, 'reserved_76': 0x76, 'reserved_77': 0x77, 'status_byte': 0x78, 'status_word': 0x79, 'status_vout': 0x7a, 'status_iout': 0x7b, 'status_input': 0x7c, 'status_temperature': 0x7d, 'status_cml': 0x7e, 'status_other': 0x7f, 'status_mfr_specific': 0x80, 'status_fans_1_2': 0x81, 'status_fans_3_4': 0x82, 'read_kwh_in': 0x83, 'read_kwh_out': 0x84, 'read_kwh_config': 0x85, 'read_ein': 0x86, 'read_eout': 0x87, 'read_vin': 0x88, 'read_iin': 0x89, 'read_vcap': 0x8a, 'read_vout': 0x8b, 'read_iout': 0x8c, 'read_temperature_1': 0x8d, 'read_temperature_2': 0x8e, 'read_temperature_3': 0x8f, 'read_fan_speed_1': 0x90, 'read_fan_speed_2': 0x91, 'read_fan_speed_3': 0x92, 'read_fan_speed_4': 0x93, 'read_duty_cycle': 0x94, 'read_frequency': 0x95, 'read_pout': 0x96, 'read_pin': 0x97, 'pmbus_revision': 0x98, 'mfr_id': 0x99, 'mfr_model': 0x9a, 'mfr_revision': 0x9b, 'mfr_location': 0x9c, 'mfr_date': 0x9d, 'mfr_serial': 0x9e, 'app_profile_support': 0x9f, 'mfr_vin_min': 0xa0, 'mfr_vin_max': 0xa1, 'mfr_iin_max': 0xa2, 'mfr_pin_max': 0xa3, 'mfr_vout_min': 0xa4, 'mfr_vout_max': 0xa5, 'mfr_iout_max': 0xa6, 'mfr_pout_max': 0xa7, 'mfr_tambient_max': 0xa8, 'mfr_tambient_min': 0xa9, 'mfr_efficiency_ll': 0xaa, 'mfr_efficiency_hl': 0xab, 'mfr_pin_accuracy': 0xac, 'ic_device_id': 0xad, 'ic_device_rev': 0xae, 'reserved_af': 0xaf, 'user_data_00': 0xb0, 'user_data_01': 0xb1, 'user_data_02': 0xb2, 'user_data_03': 0xb3, 'user_data_04': 0xb4, 'user_data_05': 0xb5, 'user_data_06': 0xb6, 'user_data_07': 0xb7, 'user_data_08': 0xb8, 'user_data_09': 0xb9, 'user_data_10': 0xba, 'user_data_11': 0xbb, 'user_data_12': 0xbc, 'user_data_13': 0xbd, 'user_data_14': 0xbe, 'user_data_15': 0xbf, 'mfr_max_temp_1': 0xc0, 'mfr_max_temp_2': 0xc1, 'mfr_max_temp_3': 0xc2, 'reserved_c3': 0xc3, 'mfr_specific_c4': 0xc4, 'mfr_specific_c5': 0xc5, 'mfr_specific_c6': 0xc6, 'mfr_specific_c7': 0xc7, 'mfr_specific_c8': 0xc8, 'mfr_specific_c9': 0xc9, 'mfr_specific_ca': 0xca, 'mfr_specific_cb': 0xcb, 'mfr_specific_cc': 0xcc, 'mfr_specific_cd': 0xcd, 'mfr_specific_ce': 0xce, 'mfr_specific_cf': 0xcf, 'mfr_specific_d0': 0xd0, 'mfr_specific_d1': 0xd1, 'mfr_specific_d2': 0xd2, 'mfr_specific_d3': 0xd3, 'mfr_specific_d4': 0xd4, 'mfr_specific_d5': 0xd5, 'mfr_specific_d6': 0xd6, 'mfr_specific_d7': 0xd7, 'mfr_specific_d8': 0xd8, 'mfr_specific_d9': 0xd9, 'mfr_specific_da': 0xda, 'mfr_specific_db': 0xdb, 'mfr_specific_dc': 0xdc, 'mfr_specific_dd': 0xdd, 'mfr_specific_de': 0xde, 'mfr_specific_df': 0xdf, 'mfr_specific_e0': 0xe0, 'mfr_specific_e1': 0xe1, 'mfr_specific_e2': 0xe2, 'mfr_specific_e3': 0xe3, 'mfr_specific_e4': 0xe4, 'mfr_specific_e5': 0xe5, 'mfr_specific_e6': 0xe6, 'mfr_specific_e7': 0xe7, 'mfr_specific_e8': 0xe8, 'mfr_specific_e9': 0xe9, 'mfr_specific_ea': 0xea, 'mfr_specific_eb': 0xeb, 'mfr_specific_ec': 0xec, 'mfr_specific_ed': 0xed, 'mfr_specific_ee': 0xee, 'mfr_specific_ef': 0xef, 'mfr_specific_f0': 0xf0, 'mfr_specific_f1': 0xf1, 'mfr_specific_f2': 0xf2, 'mfr_specific_f3': 0xf3, 'mfr_specific_f4': 0xf4, 'mfr_specific_f5': 0xf5, 'mfr_specific_f6': 0xf6, 'mfr_specific_f7': 0xf7, 'mfr_specific_f8': 0xf8, 'mfr_specific_f9': 0xf9, 'mfr_specific_fa': 0xfa, 'mfr_specific_fb': 0xfb, 'mfr_specific_fc': 0xfc, 'mfr_specific_fd': 0xfd, 'mfr_specific_command': 0xfe, 'pmbus_command_ext': 0xff}  # noqa: E501

    commands = toNametuple(pmbus_dict)

    def get_crc(self, val, byteorder: str = 'big'):
        """
        Parameters
        ----------
        val (int): value or message to parse for CRC8 using X^8+X^2+X+1
        byteorder (str): 'big' default or 'little' for endianess of the message

        Returns
        -------
        int : CRC byte

        """
        crc = 0  # initialize
        PECtable = [0, 7, 14, 9, 28, 27, 18, 21, 56, 63, 54, 49, 36, 35, 42, 45, 112, 119, 126, 121, 108, 107, 98, 101, 72, 79, 70,  65, 84, 83, 90, 93, 224, 231, 238, 233, 252, 251, 242, 245, 216, 223, 214, 209, 196, 195, 202, 205, 144, 151, 158, 153, 140, 139, 130, 133, 168, 175, 166, 161, 180, 179, 186, 189, 199, 192, 201, 206, 219, 220, 213, 210, 255, 248, 241, 246, 227, 228, 237, 234, 183, 176, 185, 190, 171, 172, 165, 162, 143, 136, 129, 134, 147, 148, 157, 154, 39, 32, 41, 46, 59, 60, 53, 50, 31, 24, 17, 22, 3, 4, 13, 10, 87, 80, 89, 94, 75, 76, 69, 66, 111, 104, 97, 102, 115, 116, 125, 122, 137, 142, 135, 128, 149, 146, 155, 156, 177, 182, 191, 184, 173, 170, 163, 164, 249, 254, 247, 240, 229, 226, 235, 236, 193, 198, 207, 200, 221, 218, 211, 212, 105, 110, 103, 96, 117, 114, 123, 124, 81, 86, 95, 88, 77, 74, 67, 68, 25, 30, 23, 16, 5, 2, 11, 12, 33, 38, 47, 40, 61, 58, 51, 52, 78, 73, 64, 71, 82, 85, 92, 91, 118, 113, 120, 127, 106, 109, 100, 99, 62, 57, 48, 55, 34, 37, 44, 43, 6, 1, 8, 15, 26, 29, 20, 19, 174, 169, 160, 167, 178, 181, 188, 187, 150, 145, 152, 159, 138, 141, 132, 131, 222, 217, 208, 215, 194, 197, 204, 203, 230, 225, 232, 239, 250, 253, 244, 243]  # noqa: E501
        # CRC8 lookup table for PMBus

        message = val.to_bytes((val.bit_length() + 7) // 8,
                               byteorder=byteorder, signed=False)
        for i in range(len(message)):
            pecindex = crc ^ message[i]
            crc = PECtable[pecindex]

        return crc

    def fault_response(self, cmd, response, retry, delay,
                       doRead: bool = False,
                       **kwargs) -> "tuple(int, int, int)":
        """fault_response is a generic PMBus Fault Response command
        if any of response, retry or delay are passed as not None
        then the command will set the fault response and return the device
        value read (some devices will reject all or portions of a fault
        response setup value depending on their capabilities).
        if they are all None, then the command will only read the device
        setting without modification.

        Returns:
            tuple(int, int, int): response, retry, delay
            if these values are not passed in, they may return None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        dowrite = False
        assembly = 0
        if response is not None:
            dowrite = True  # can't use | because NoneType
            assembly = assembly | ((response & 0x03) << 6)
        if retry is not None:
            dowrite = True  # can't use | because NoneType
            assembly = assembly | ((retry & 0x07) << 3)
        if delay is not None:
            dowrite = True  # can't use | because NoneType
            assembly = assembly | (delay & 0x07)

        if dowrite:
            self.write_slave([cmd, int(assembly)], **kwargs)

        if doRead or not dowrite:
            message = self.query_slave([cmd], 1, **kwargs)
            message = int.from_bytes(message, byteorder='little', signed=False)
            response = (message & (0x03 << 6)) >> 6
            retry = (message & (0x07 << 3)) >> 3
            delay = (message & 0x07)

        return (response, retry, delay)

    def get_pmbus_two(self, cmd: int, byteorder: str, signed: bool,
                      **kwargs) -> int:
        """get_pmbus_two is a generic 2-byte read with bytes to int decoder

        Args:
            cmd (int): pmbus command to execute
            byteorder (str): 'little' or 'big'
            signed (bool): decode bytes as signed or unsigned int

        Returns:
            int: pmbus return int, signed or unsigned as indicated
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([cmd], 2, **kwargs)
        response = int.from_bytes(response, byteorder=byteorder, signed=signed)
        return response

    def set_pmbus_two(self, item: int, cmd: int, byteorder: str, signed: bool,
                      **kwargs) -> None:
        """set_pmbus_two generic two-byte pmbus command writer

        Args:
            item (int): 2-byte integer data to send to device
            cmd (int): pmbus command to send to device with data
            byteorder (str): 'little' or 'big' endian for item
            signed (bool): are the data bytes in item signed?

        Returns:
            [None]:
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        sendbytes = item.to_bytes(2, byteorder=byteorder, signed=signed)
        self.write_slave([cmd, *sendbytes], **kwargs)
        return None

    # static variables in the controller
    # None

    # methods that implement the IC's opcodes
    def get_page(self, **kwargs) -> int:
        """
        page()

        reads back the page currently set in the slave device

        Args:
            None

        Returns:
            int: page set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.operation], 1, **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def set_page(self, page: int, **kwargs) -> None:
        """
        page()

        will set the page in the slave device

        Args:
            page (int): if provided will set the page

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.page, page], **kwargs)
        return None

    @property
    def page(self) -> int:
        """
        page()

        reads back the page currently set in the slave device
        if page is provided will set the page

        Args:
            page (int): if provided will set the page

        Returns:
            int: page set in slave, unsigned, 1 byte
        """
        self._page = self.get_page()
        return self._page

    @page.setter
    def page(self, page: int) -> int:
        """
        page()

        reads back the page currently set in the slave device
        if page is provided will set the page

        Args:
            page (int): if provided will set the page

        Returns:
            int: page set in slave, unsigned, 1 byte
        """
        self.set_operation(page)
        return

    def get_operation(self, **kwargs) -> int:
        """
        operation()

        reads back the operation currently set in the slave device
        if operation is provided will set the operation

        Args:
            operation (int): if provided will set the operation

        Returns:
            int: operation set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.operation], 1, **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def set_operation(self, operation: int, **kwargs) -> None:
        """
        operation()

        reads back the operation currently set in the slave device
        if operation is provided will set the operation

        Args:
            operation (int): if provided will set the operation

        Returns:
            int: operation set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.operation, operation], **kwargs)
        return None

    @property
    def operation(self) -> int:
        """
        operation()
        reads back the operation currently set in the slave device

        Args:
            None

        Returns:
            int: operation set in slave, unsigned, 1 byte
        """
        self._operation = self.get_operation()
        return self._operation

    @operation.setter
    def operation(self, operation: int) -> int:
        """
        operation()
        attempts to set the operation in the slave device

        Args:
            operation (int): set the operation

        Returns:
            int: operation sent to slave, not necessarily accepted,
            unsigned, 1 byte
        """
        self.set_operation(operation)
        return

    def get_on_off_config(self, **kwargs) -> int:
        """
        on_off_config()

        reads back the on_off_config currently set in the slave device

        Returns:
            int: on_off_config set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.operation], 1, **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def set_on_off_config(self, on_off_config: int, **kwargs) -> None:
        """
        on_off_config()

        will set the on_off_config

        Args:
            on_off_config (int): if provided will set the on_off_config

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.on_off_config, on_off_config],
                         **kwargs)
        return None

    @property
    def on_off_config(self) -> int:
        self._on_off_config = self.get_on_off_config()
        return self._on_off_config

    @on_off_config.setter
    def on_off_config(self, on_off_config) -> None:
        self.set_on_off_config(on_off_config)
        return

    def clear_faults(self, **kwargs) -> None:
        """
        clear_faults()

        clears faults in the slave

        Args:
            None

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.clear_faults], **kwargs)

        return None

    def phase(self, phase=None, **kwargs) -> int:
        """
        phase()

        reads back the phase currently set in the slave device
        if phase is provided will set the phase

        Args:
            phase (int): if provided will set the phase

        Returns:
            int: phase set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        if phase:
            response = self.query_slave([self.commands.phase, int(phase)], 1,
                                        **kwargs)
        else:
            response = self.query_slave([self.commands.phase], 1, **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def page_plus_write(self, page, command_code, data, pec: bool = False,
                        byteorder: str = 'little', **kwargs) -> None:
        """
        page_plus_write()

        The PAGE_PLUS_WRITE command is used to set the page within a device,
        send a
        command, and send the data for the command in one packet.
        The PAGE_PLUS_WRITE command uses the WRITE BLOCK protocol.

        Args:
            page (int): the page to write
            command_code (int): command to send
            data (int): data to send, it will be sent in little endian, unless
            byteorder is set in kwargs
            pec (bool): send PEC byte or not.

        Returns:
            None
        *data is a generator

        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        message = bytearray()
        data_length = int((data.bit_length() + 7) // 8)
        message.append(self.commands.page_plus_write)
        message.append(int(data_length + 2))
        message.append(int(page))
        message.append(int(command_code))
        message.append(int.to_bytes(data_length, byteorder=byteorder,
                                    signed=False))
        if pec:
            pecbyte = self.get_crc(message)
            message.append(pecbyte)

        self.write_slave(*message, **kwargs)

        return None

    def page_plus_read(self, page, command_code, data, block_count: int = 4,
                       pec: bool = False, retry_count: int = 1,
                       retry: bool = False, **kwargs) -> "tuple(int, bool)":
        """
        page_plus_read()

        The PAGE_PLUS_READ command is used to set the page within a device,
        send a
        command, and read the data returned by the command in one packet.
        The PAGE_PLUS_READ command uses the BLOCK WRITE – BLOCK READ
        PROCESS CALL protocol.

        Args:
            block_count (int): number of bytes to expect in the write after
            this byte
            page (int): the page to write
            command_code (int): command to send
            data (int): data to send, it will be sent in little endian
            pec (bool): send PEC byte or not.

        Returns:
            None
        *data is a generator

        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        data = bytearray()
        data.append(self.commands.page_plus_read)
        data.append(int(page))
        data.append(int(command_code))
        read_len = block_count - 2 + pec  # pec is bool, true=1, false=0

        i = 0
        while i < retry_count:
            response = self.query_slave(*data, read_len, **kwargs)
            if pec:
                # we want to know the pec from what we sent and received
                # matches the pec byte received
                # first we'll get all of the response before the received
                # pec and append that to what we sent
                # next store the received pec
                # call get_crc and lookup the correct pec
                # compare
                # if kwargs says to retry we will repeat once if pec is bad
                length = len(response) - 1  # len comes back counting from 1
                pecdata = bytearray()
                pecdata.append(data)
                pecdata.append(response[0:length-1])  # everyting but the pec
                rxpec = response[length]  # the pec byte received
                pecbyte = self.get_crc(data)  # go get the pec
                if rxpec == pecbyte:
                    crc = True
                    break
                else:
                    if retry:
                        i += 1
                    else:
                        crc = False
                        break
            else:
                crc = True
                break
        response = int.from_bytes(response, byteorder='big', signed=False)

        return (response, crc)

    def zone_config(self, zone_write, zone_read,
                    **kwargs) -> "tuple(int, int)":
        """
        zone_config(zone_write, zone_read)

        The ZONE_CONFIG command is used to assign a PMBus device, which may
        be a
        discrete entity at one PMBus address, or a PAGE within an entity on
        the PMBus, to a
        specific zone number for ZONE_READ operations and to a specific zone
        number for
        ZONE_WRITE operations.
        A device’s write or read zone may be assigned one of 129 possible zone
        numbers,
        ranging from 00h to 7Fh plus FEh. A device’s write zone and read zone
        do not have to
        be the same.
        A device’s read zone and/or write zone may be assigned to the “No Zone”
        by
        assigning the device’s read zone and/or write zone the value FEh. A
        device whose
        assigned read zone is FEh shall ignore all ZONE_READ operations. A
        device whose
        assigned write zone is FEh shall ignore all ZONE_WRITE operations.
        Assigning a
        device to the “No Zone” is used to prevent a zone-capable device from
        participating in
        zone operations.
        Zone values 80h through BFh are reserved for PMBus product
        manufacturer’s
        definition. Zone values C0h to FDh are reserved for future use
        by this specification.
        Args:
            zone_config (int): if provided will set the zone_config

        Returns:
            tuple(int, int): zone_write, zone_read
            zone_write set in slave, unsigned, 1 byte
            zone_read set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.zone_config, int(zone_write),
                          int(zone_read)], **kwargs)

        return (zone_write, zone_read)

    def zone_active(self, zone_active_write: int = 0xFE,
                    zone_active_read: int = 0xFE,
                    **kwargs) -> "tuple(int, int)":
        """
        zone_active(zone_active_write, zone_active_read)

        The ZONE_ACTIVE command is used by the master to set the Active
        Write Zone for
        ZONE_WRITE operations and the Active Read Zone for ZONE_READ
        operations.
        The active zone setting is a property of the entire system attached
        to a given physical
        PMBus and is not a property of an individual device attached to
        that bus.
        The ZONE_ACTIVE command has two data bytes. The first data byte is
        the active
        zone number for write operations (Active Write Zone). The second
        data byte is the
        active zone number for read operations (Active Read Zone).
        All devices that support zone operations shall respond to the
        ZONE_ACTIVE
        command regardless of their current configuration for read and
        write zones. If a
        device has its write zone configured to the “No Zone” (FEh) it
        shall ignore the Active
        Write Zone value. If a device has its read zone configured to the
        “No Zone” it shall
        ignore the Active Read Zone value.
        Values of 00h to 7Fh are used for normal active zones.

        Args:
            zone_active (int): if provided will set the zone_active

        Returns:
            tuple(int, int):
            zone_active_write (int): set in slave, unsigned, 1 byte
            zone_active_read (int): set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        if zone_active_write == 0xFE and zone_active_read == 0xFE:
            response = self.query_slave([self.commands.zone_active], 2,
                                        **kwargs)
            zone_active_write = response[0]
            zone_active_read = response[1]

        else:
            kwargs['relax'] = True  # special case
            self.write_slave([self.commands.zone_active,
                              int(zone_active_write),
                              int(zone_active_read)],
                             **kwargs)

        return (zone_active_write, zone_active_read)

    def write_protect(self, write_protect: int = 0x00, **kwargs) -> None:
        """
        write_protect(write_protect)

        The WRITE_PROTECT command is used to control writing to the PMBus
        device. The
        intent of this command is to provide protection against accidental
        changes. This
        command is not intended to provide protection against deliberate or
        malicious changes
        to a device’s configuration or operation.
        All supported commands may have their parameters read, regardless
        of the
        WRITE_PROTECT settings.

        Args:
            write_protect (int): set the write_protect
                Data Byte Value Meaning
                0x80, 1000 0000 Disable all writes except to the WRITE_PROTECT
                command
                0x40, 0100 0000 Disable all writes except to the WRITE_PROTECT,
                OPERATION and
                PAGE commands
                0x20, 0010 0000 Disable all writes except to the WRITE_PROTECT,
                OPERATION,
                PAGE, ON_OFF_CONFIG and VOUT_COMMAND commands
                0x03, 0000 0011 Manufacturer specified
                0x02, 0000 0010 Manufacturer specified
                0x01, 0000 0001 Manufacturer specified
                0x00, 0000 0000 Enable writes to all commands.
        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.write_protect, int(write_protect)],
                         **kwargs)

        return None

    def store_default_all(self, **kwargs) -> None:
        """
        store_default_all()

        write only
        The STORE_DEFAULT_ALL command instructs the PMBus device to copy the
        entire
        contents of the Operating Memory to the matching locations in the
        non-volatile Default
        Store memory. Any items in Operating Memory that do not have matching
        locations in
        the Default Store are ignored.

        Args:
            None

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        self.write_slave([self.commands.store_default_all],
                         **kwargs)

        return None

    def restore_default_all(self, **kwargs) -> None:
        """
        restore_default_all()

        This command is write only.
        The RESTORE_DEFAULT_ALL command instructs the PMBus device to copy
        the entire
        contents of the non-volatile Default Store memory to the matching
        locations in the
        Operating Memory. The values in the Operating Memory are overwritten
        by the value
        retrieved from the Default Store. Any items in Default Store that do
        not have matching
        locations in the Operating Memory are ignored.

        Args:
            None

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        self.write_slave([self.commands.restore_default_all], **kwargs)

        return None

    def store_default_code(self, command_code, **kwargs) -> None:
        """
        store_default_code()

        The STORE_DEFAULT_CODE command instructs the PMBus device to copy the
        parameter whose Command Code matches the value in the data byte,
        from the
        Operating Memory to the matching location in the non-volatile Default
        Store memory.

        Args:
            store_default_code (int): will store the store_default_code

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        self.write_slave([self.commands.store_default_code,
                          int(command_code)], **kwargs)

        return None

    def restore_default_code(self, command_code, **kwargs) -> None:
        """
        restore_default_code()

        The RESTORE_DEFAULT_CODE command instructs the device to copy the
        parameter
        whose Command Code matches the value in the data byte from the
        non-volatile Default
        Store memory to the matching location in the Operating Memory.
        The value in the
        Operating Memory is overwritten by the value retrieved from the
        Default Store.

        Args:
            restore_default_code (int):  will restore the restore_default_code

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        self.write_slave([self.commands.store_default_code,
                          int(command_code)], **kwargs)

        return None

    def store_user_all(self, **kwargs) -> None:
        """
        store_user_all()

        The STORE_USER_ALL command instructs the PMBus device to copy
        the entire
        contents of the Operating Memory to the matching locations in
        the non-volatile User
        Store memory. Any items in Operating Memory that do not have
        matching locations in
        the User Store are ignored.

        Args:
            None

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        self.write_slave([self.commands.store_user_all], **kwargs)

        return None

    def restore_user_all(self, **kwargs) -> None:
        """
        restore_user_all()

        The restore_user_all command instructs the PMBus device to copy
        the entire
        contents of the Operating Memory to the matching locations in the
        non-volatile User
        Store memory. Any items in Operating Memory that do not have matching
        locations in
        the User Store are ignored.

        Args:
            None

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        self.write_slave([self.commands.restore_user_all], **kwargs)

        return None

    def store_user_code(self, command_code, **kwargs) -> None:
        """
        store_user_code()

        will set the store_user_code for command_code

        Args:
            command_code (int): will store the store_user_code

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        self.write_slave([self.commands.store_user_code,
                          int(command_code)], **kwargs)

        return None

    def restore_user_code(self, command_code, **kwargs) -> None:
        """
        restore_user_code(command_code)

        will restore the command_code

        Args:
            restore_user_code (int):  will restore the restore_user_code

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)

        self.write_slave([self.commands.restore_user_code,
                          int(command_code)], **kwargs)

        return None

    def capability(self, **kwargs) -> int:
        """
        capability()

        This command provides a way for a host system to determine some
        key capabilities of a
        PMBus device.
        There is one data byte formatted as shown in Table 7.
        This command is read only.

        Args:
            None

        Returns:
            int: capability set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.capability], 1, **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def query(self, command_code: int, **kwargs) -> int:
        """
        query(command_code)

        The QUERY command is used to ask a PMBus device if it supports a
        given command,
        and if so, what data formats it supports for that command.

        Args:
            command_code (int): command_code to query about

        Returns:
            int: command_code support description
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.query, command_code], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def get_alert_response_address(self, **kwargs) -> int:
        """get_alert_response_address()
        A slave-only device can signal the host through SMBALERT# that it
        wants to talk. The host processes the interrupt and simultaneously
        accesses all SMBALERT# devices through the Alert Response Address.
        Only the device(s) which pulled SMBALERT# low will acknowledge the
        Alert Response Address. The host performs a modified Receive Byte
        operation. The 7 bit device address provided by the slave transmit
        device is placed in the 7 most significant bits of the byte.
        The eighth bit can be a zero or one.

        Returns:
            int: highest priority (lowest address) device address which has
            SMBAlert# data to transfer.
            If no devices need to be polled the address return is zero.
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        response = self.ara_query(**kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def get_smbalert_mask(self, status_x, **kwargs) -> int:
        if isinstance(status_x, str):
            if status_x == 'STATUS_BYTE':
                x = 0x78
            elif status_x == 'STATUS_WORD':
                x = 0x79
            elif status_x == 'STATUS_VOUT':
                x = 0x7A
            elif status_x == 'STATUS_IOUT':
                x = 0x7B
            elif status_x == 'STATUS_INPUT':
                x = 0x7C
            elif status_x == 'STATUS_TEMP':
                x = 0x7D
            elif status_x == 'STATUS_CML':
                x = 0x7E
            elif status_x == 'STATUS_OTHER':
                x = 0x7F
            elif status_x == 'STATUS_MFR_SPECIFIC':
                x = 0x80
            elif status_x == 'STATUS_FANS_1_2':
                x = 0x81
            elif status_x == 'STATUS_FANS_3_4':
                x = 0x82
            else:
                raise print(f'input error: {status_x} unknown..')
        elif isinstance(status_x, int):
            x = status_x

        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        mask = self.query_slave([self.commands.smbalert_mask, int(1), x], 2,
                                **kwargs)
        # this is block read, first byte back is the read block count
        return mask[1]

    def set_smbalert_mask(self, status_x, mask: int, **kwargs) -> None:
        if isinstance(status_x, str):
            if status_x == 'STATUS_BYTE':
                x = 0x78
            elif status_x == 'STATUS_WORD':
                x = 0x79
            elif status_x == 'STATUS_VOUT':
                x = 0x7A
            elif status_x == 'STATUS_IOUT':
                x = 0x7B
            elif status_x == 'STATUS_INPUT':
                x = 0x7C
            elif status_x == 'STATUS_TEMP':
                x = 0x7D
            elif status_x == 'STATUS_CML':
                x = 0x7E
            elif status_x == 'STATUS_OTHER':
                x = 0x7F
            elif status_x == 'STATUS_MFR_SPECIFIC':
                x = 0x80
            elif status_x == 'STATUS_FANS_1_2':
                x = 0x81
            elif status_x == 'STATUS_FANS_3_4':
                x = 0x82
            else:
                raise print(f'input error: {status_x} unknown..')
        elif isinstance(status_x, int):
            x = status_x

        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        mask = self.write_slave([self.commands.smbalert_mask, x, mask],
                                **kwargs)
        # this is block read, first byte back is the read block count
        return None

    def smbalert_mask(self, status_x, **kwargs):
        """
        smbalert_mask(status_x, mask)

        reads back the smbalert_mask currently set in the slave device
        if status_x is provided will set the smbalert_mask for that register
        The SMBALERT_MASK command may be used to prevent a warning or fault
        condition
        from asserting the SMBALERT# signal.

        Args:
            status_x (int): the smbalert_register to read or set
            smbalert_mask for
            mask (int): if provided will set the smbalert_mask, if not
            provided returns the mask in the slave

        Returns:
            int: mask set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        if 'mask' in kwargs:
            smbalert_mask = kwargs['mask']
            del kwargs['mask']
            kwargs['relax'] = True  # special case
            self.write_slave([self.commands.smbalert_mask, int(status_x),
                              int(smbalert_mask)], **kwargs)
        else:
            mask = self.query_slave([self.commands.smbalert_mask, int(1),
                                     int(status_x)], 2, **kwargs)
            # this is block read, first byte back is the read block count
        return mask[1]

    def get_vout_mode(self, **kwargs) -> int:
        """
        vout_mode(mode)

        reads back the vout_mode currently set in the slave device
        if mode is provided will attempt to set the vout_mode
        if the slave vout_mode is read only it will reject

        Args:
            mode (int): if provided will set the vout_mode

        Returns:
            int: mode set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.vout_mode], 1, **kwargs)
        mode = int.from_bytes(response, byteorder='little', signed=False)
        return mode

    def set_vout_mode(self, mode: int, **kwargs) -> None:
        """
        vout_mode(mode)

        reads back the vout_mode currently set in the slave device
        if mode is provided will attempt to set the vout_mode
        if the slave vout_mode is read only it will reject

        Args:
            mode (int): will attempt to set the vout_mode

        Returns:
            None
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.vout_mode, int(mode)], **kwargs)
        return

    @property
    def vout_mode(self) -> int:
        self._vout_mode = self.get_vout_mode()
        self.decode_vout_mode(self._vout_mode)
        return self._vout_mode

    @vout_mode.setter
    def vout_mode(self, mode) -> None:
        self.set_vout_mode(mode)
        return

    def decode_vout_mode(self, mode) -> "tuple(str, int, int, int)":
        absolute_relative = (mode & 0x80) >> 7
        mode_kind = (mode & 0x60) >> 5
        if mode_kind == 0:
            mode_str = 'ULINEAR16'
        elif mode_kind == 1:
            mode_str = 'VID'
        elif mode_kind == 2:
            mode_str = 'DIRECT'
        elif mode_kind == 3:
            mode_str = 'IEEE'
        exponent = self.twos_complement(mode & 0x1F, 5)
        self._vout_mode_str = mode_str
        self._vout_mode_absolute_relative = absolute_relative
        self._vout_mode_exponent = exponent
        return (mode_str, absolute_relative, exponent)

    def encode_vout_mode(self, mode_str, absolute_relative,
                         exponent) -> "tuple(str, int, int, int)":
        mode = self._vout_mode
        if absolute_relative is not None:
            absolute_relative = absolute_relative << 7
            mode = (mode & ~0x80)
            mode = mode | absolute_relative
        if mode_str is not None:
            if mode_str == 'ULINEAR16':
                mode_kind = 0
            elif mode_str == 'VID':
                mode_kind = 1
            elif mode_str == 'DIRECT':
                mode_kind = 2
            elif mode_str == 'IEEE':
                mode_kind = 3
            mode_kind = mode_kind << 5
            mode = (mode & ~0x60)
            mode = mode | mode_kind
        if exponent is not None:
            exponent = self.twos_complement(exponent & 0x1F, 5,
                                            reverse=True)
            mode = (mode & ~0x1F)
            mode = mode | exponent
        self._vout_mode = mode
        return self._vout_mode

    @property
    def vout_mode_exponent(self) -> int:
        self.vout_mode
        return self._vout_mode_exponent

    @vout_mode_exponent.setter
    def vout_mode_exponent(self, exponent: int) -> None:
        self.vout_mode = self.encode_vout_mode(None, None, exponent)
        return

    @property
    def vout_mode_str(self) -> str:
        self.vout_mode
        return self._vout_mode_str

    @vout_mode_str.setter
    def vout_mode_str(self, mode_str: str) -> None:
        self.vout_mode = self.encode_vout_mode(mode_str, None, None)
        return

    @property
    def vout_mode_absolute_relative(self) -> str:
        self.vout_mode
        return self._vout_mode_absolute_relative

    @vout_mode_absolute_relative.setter
    def vout_mode_absolute_relative(self, absolute_relative: int) -> None:
        self.vout_mode = self.encode_vout_mode(None, absolute_relative, None)
        return

    def get_vout_command(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_command,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_command(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_command,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_command(self) -> int:
        """
        vout_command()

        reads back the vout_command currently set in the slave device
        if vout is provided will set the vout

        Args:
            vout (int): if provided will set the vout

        Returns:
            int: vout_command set in slave, unsigned, 1 byte
        """
        self._vout_command = self.get_vout_command()
        return self._vout_command

    @vout_command.setter
    def vout_command(self, vout: int) -> None:
        self.set_vout_command(vout)
        return None

    def get_vout_trim(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_trim,
                                  byteorder='little', signed=True, **kwargs)

    def set_vout_trim(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_trim,
                           byteorder='little', signed=True, **kwargs)
        return None

    @property
    def vout_trim(self) -> int:
        """
        vout_trim()

        reads back the vout_trim currently set in the slave device
        if trim is provided will set the vout_trim
        The VOUT_TRIM command is used to apply a fixed offset voltage to
        the output voltage
        command value. It is most typically used by the end user to trim
        the output voltage at
        the time the PMBus device is assembled into the end user’s system.
        The VOUT_TRIM has two data bytes formatted as a two’s complement
        binary integer
        (SLINEAR16 format). The effect of this command depends on the
        settings of the
        VOUT_MODE command (Section 8).

        Args:
            trim (int): if provided will set the vout_trim

        Returns:
            int: trim set in slave, signed, 2 byte
        """
        self._vout_trim = self.get_vout_trim()
        return self._vout_trim

    @vout_trim.setter
    def vout_trim(self, vout: int) -> None:
        self.set_vout_trim(vout)
        return None

    def get_vout_cal_offset(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_cal_offset,
                                  byteorder='little', signed=True, **kwargs)

    def set_vout_cal_offset(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_cal_offset,
                           byteorder='little', signed=True, **kwargs)
        return None

    @property
    def vout_cal_offset(self):
        """
        vout_cal_offset()

        reads back the vout_cal_offset currently set in the slave device
        if cal is provided will set the vout_cal_offset
        The VOUT_CAL_OFFSET command is used to apply a fixed offset voltage
        to the output
        voltage command value. It is most typically used by the PMBus device
        manufacturer to
        calibrate a device in the factory.
        The VOUT_CAL_OFFSET has two data bytes formatted as a two’s
        complement binary
        integer (SLINEAR16 format). The effect of this command depends on
        the settings of the
        VOUT_MODE command (Section 8).

        Args:
            cal (int): if provided will set the vout_cal_offset

        Returns:
            int: cal set in slave, signed, 2 byte
        """
        self._vout_cal_offset = self.get_vout_cal_offset()
        return self._vout_cal_offset

    @vout_cal_offset.setter
    def vout_cal_offset(self, vout: int) -> None:
        self.set_vout_cal_offset(vout)
        return None

    def get_vout_max(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_max,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_max(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_max,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_max(self):
        """
        vout_max()

        reads back the vout_max currently set in the slave device
        if vout is provided will set the vout_max

        Args:
            vout (int): if provided will set the vout_max

        Returns:
            int: vout_max set in slave, unsigned, 2 byte
        """
        self._vout_max = self.get_vout_max()
        return self._vout_max

    @vout_max.setter
    def vout_max(self, vout: int) -> None:
        self.set_vout_max(vout)
        return None

    def get_vout_margin_high(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_margin_high,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_margin_high(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_margin_high,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_margin_high(self):
        """
        vout_margin_high()

        reads back the vout_margin_high currently set in the slave device
        if vout is provided will set the vout_margin_high

        Args:
            vout (int): if provided will set the vout_margin_high

        Returns:
            int: vout_margin_high set in slave, unsigned, 2 byte
        """
        self._vout_margin_high = self.get_vout_margin_high()
        return self._vout_margin_high

    @vout_margin_high.setter
    def vout_margin_high(self, vout: int) -> None:
        self.set_vout_margin_high(vout)
        return None

    def get_vout_margin_low(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_margin_low,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_margin_low(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_margin_low,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_margin_low(self):
        """
        vout_margin_low()

        reads back the vout_margin_low currently set in the slave device
        if vout is provided will set the vout_margin_low

        Args:
            vout (int): if provided will set the vout_margin_low

        Returns:
            int: vout_margin_low set in slave, unsigned, 2 byte
        """
        self._vout_margin_low = self.get_vout_margin_low()
        return self._vout_margin_low

    @vout_margin_low.setter
    def vout_margin_low(self, vout: int) -> None:
        self.set_vout_margin_low(vout)
        return None

    def get_vout_transition_rate(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_transition_rate,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_transition_rate(self, slewrate: int, **kwargs) -> None:
        self.set_pmbus_two(slewrate, self.commands.vout_transition_rate,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_transition_rate(self):
        """
        vout_transition_rate()

        reads back the vout_transition_rate currently set in the slave device
        if slewrate is provided will set the vout_transition_rate

        Args:
            slewrate (int): if provided will set the vout_transition_rate

        Returns:
            int: vout_transition_rate set in slave, unsigned, 2 byte
        """
        self._vout_transition_rate = self.get_vout_transition_rate()
        return self._vout_transition_rate

    @vout_transition_rate.setter
    def vout_transition_rate(self, slewrate: int) -> None:
        self.set_vout_transition_rate(slewrate)
        return None

    def get_vout_droop(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_droop,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_droop(self, droop: int, **kwargs) -> None:
        self.set_pmbus_two(droop, self.commands.vout_droop,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_droop(self):
        """
        vout_droop()

        reads back the vout_droop currently set in the slave device
        if droop is provided will set the vout_droop

        Args:
            droop (int): if provided will set the vout_droop

        Returns:
            int: vout_droop set in slave, unsigned, 2 byte
        """
        self._vout_droop = self.get_vout_droop()
        return self._vout_droop

    @vout_droop.setter
    def vout_droop(self, droop: int) -> None:
        self.set_vout_droop(droop)
        return None

    def get_vout_scale_loop(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_scale_loop,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_scale_loop(self, scale: int, **kwargs) -> None:
        self.set_pmbus_two(scale, self.commands.vout_scale_loop,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_scale_loop(self):
        """
        vout_scale_loop()

        reads back the vout_scale_loop currently set in the slave device
        if scale is provided will set the vout_scale_loop

        Args:
            scale (int): if provided will set the vout_scale_loop

        Returns:
            int: vout_scale_loop set in slave, unsigned, 2 byte
        """
        self._vout_scale_loop = self.get_vout_scale_loop()
        return self._vout_scale_loop

    @vout_scale_loop.setter
    def vout_scale_loop(self, scale: int) -> None:
        self.set_vout_scale_loop(scale)
        return None

    def get_vout_scale_monitor(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_scale_monitor,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_scale_monitor(self, scale: int, **kwargs) -> None:
        self.set_pmbus_two(scale, self.commands.vout_scale_monitor,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_scale_monitor(self):
        """
        vout_scale_monitor()

        reads back the vout_scale_monitor currently set in the slave device
        if scale is provided will set the vout_scale_monitor

        Args:
            scale (int): if provided will set the vout_scale_monitor

        Returns:
            int: vout_scale_monitor set in slave, unsigned, 2 byte
        """
        self._vout_scale_monitor = self.get_vout_scale_monitor()
        return self._vout_scale_monitor

    @vout_scale_monitor.setter
    def vout_scale_monitor(self, scale: int) -> None:
        self.set_vout_scale_monitor(scale)
        return None

    def get_vout_min(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_min,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_min(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_min,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_min(self):
        """
        vout_min()

        reads back the vout_min currently set in the slave device
        if vout is provided will set the vout_min

        Args:
            vout (int): if provided will set the vout_min

        Returns:
            int: vout_min set in slave, unsigned, 2 byte
        """
        self._vout_min = self.get_vout_min()
        return self._vout_min

    @vout_min.setter
    def vout_min(self, vout: int) -> None:
        self.set_vout_min(vout)
        return None

    def coefficients(self, command_code, direction: str = 'decode', **kwargs):
        """
        coefficients(command_code, direction)

        reads back the coefficients currently set in the slave device for the
        given command_code

        Args:
            coefficients (str): decode if provided will get the coefficients
            for decoding from slave
            coefficients (str): encode if provided will get the coefficients
            for encoding to slave
            (hint, it's not supposed to matter!)

        Returns:
            m int: m coefficient set in slave, signed, 2 byte
            b int: b coefficient set in slave, signed, 2 byte
            R int: R coefficient set in slave, signed, 2 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        coeff = 0x00
        if direction == 'decode':
            coeff = 0x01
        response = self.query_slave([self.commands.coefficients, int(0x02),
                                     int(command_code), int(coeff)], 6,
                                    **kwargs)
        # need to add PEC support eventually, that would make read bytes 7
        m = int.from_bytes(response[0:2], byteorder='little', signed=True)
        b = int.from_bytes(response[2:4], byteorder='little', signed=True)
        R = int.from_bytes(response[4:6], byteorder='little', signed=True)

        return (m, b, R)

    def get_pout_max(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.pout_max,
                                  byteorder='little', signed=False, **kwargs)

    def set_pout_max(self, pout: int, **kwargs) -> None:
        self.set_pmbus_two(pout, self.commands.pout_max,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def pout_max(self, **kwargs):
        """
        pout_max()

        reads back the pout_max currently set in the slave device
        if pout is provided will set the pout_max

        Args:
            pout (int): if provided will set the pout_max

        Returns:
            int: pout_max set in slave, unsigned, 2 byte
        """
        self._pout_max = self.get_pout_max()
        return self._pout_max

    @pout_max.setter
    def pout_max(self, pout: int) -> None:
        self.set_pout_max(pout)
        return None

    def get_max_duty(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.max_duty,
                                  byteorder='little', signed=False, **kwargs)

    def set_max_duty(self, duty: int, **kwargs) -> None:
        self.set_pmbus_two(duty, self.commands.max_duty,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def max_duty(self):
        """
        max_duty()

        reads back the max_duty currently set in the slave device
        if duty is provided will set the max_duty

        Args:
            duty (int): if provided will set the max_duty

        Returns:
            int: max_duty set in slave, unsigned, 2 byte
        """
        self._max_duty = self.get_max_duty()
        return self._max_duty

    @max_duty.setter
    def max_duty(self, duty: int) -> None:
        self.set_max_duty(duty)
        return None

    def get_frequency_switch(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.frequency_switch,
                                  byteorder='little', signed=False, **kwargs)

    def set_frequency_switch(self, frequency: int, **kwargs) -> None:
        self.set_pmbus_two(frequency, self.commands.frequency_switch,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def frequency_switch(self):
        """
        frequency_switch()

        reads back the frequency_switch currently set in the slave device
        if duty is provided will set the frequency_switch

        Args:
            duty (int): if provided will set the frequency_switch

        Returns:
            int: frequency_switch set in slave, unsigned, 2 byte
        """
        self._frequency_switch = self.get_frequency_switch()
        return self._frequency_switch

    @frequency_switch.setter
    def frequency_switch(self, frequency: int) -> None:
        self.set_frequency_switch(frequency)
        return None

    def get_power_mode(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.power_mode,
                                  byteorder='little', signed=False, **kwargs)

    def set_power_mode(self, mode: int, **kwargs) -> None:
        self.set_pmbus_two(mode, self.commands.power_mode,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def power_mode(self):
        """
        power_mode()

        reads back the power_mode currently set in the slave device
        if duty is provided will set the power_mode

        Args:
            duty (int): if provided will set the power_mode

        Returns:
            int: power_mode set in slave, unsigned, 2 byte
        """
        self._power_mode = self.get_power_mode()
        return self._power_mode

    @power_mode.setter
    def power_mode(self, mode: int) -> None:
        self.set_power_mode(mode)
        return None

    def get_vin_on(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vin_on,
                                  byteorder='little', signed=False, **kwargs)

    def set_vin_on(self, vin: int, **kwargs) -> None:
        self.set_pmbus_two(vin, self.commands.vin_on,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vin_on(self):
        """
        vin_on()

        reads back the vin_on currently set in the slave device
        if duty is provided will set the vin_on

        Args:
            duty (int): if provided will set the vin_on

        Returns:
            int: vin_on set in slave, unsigned, 2 byte
        """
        self._vin_on = self.get_vin_on()
        return self._vin_on

    @vin_on.setter
    def vin_on(self, vin: int) -> None:
        self.set_vin_on(vin)
        return None

    def get_vin_off(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vin_off,
                                  byteorder='little', signed=False, **kwargs)

    def set_vin_off(self, vin: int, **kwargs) -> None:
        self.set_pmbus_two(vin, self.commands.vin_off,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vin_off(self):
        """
        vin_off()

        reads back the vin_off currently set in the slave device
        if duty is provided will set the vin_off

        Args:
            duty (int): if provided will set the vin_off

        Returns:
            int: vin_off set in slave, unsigned, 2 byte
        """
        self._vin_off = self.get_vin_off()
        return self._vin_off

    @vin_off.setter
    def vin_off(self, vin: int) -> None:
        self.set_vin_off(vin)
        return None

    def interleave(self, **kwargs):
        """
        interleave()

        reads back the interleave currently set in the slave device
        if group_id, gnum, iorder is provided will set the interleaving

        The INTERLEAVE command data bytes include three pieces of information:
        • A group identification number (4 bits),
        • The number of units in the group (4 bits) and
        • The interleave order for this particular unit (4 bits). This number
        ranges in value from
        zero to one less than the number of units in the group.
        The group identification number allows for up to fifteen groups. Group
        Identification
        Number 0 is reserved to mean not a member of an interleaved group. If
        the group
        identification number is 0, then the number of units in the group and
        the interleave order
        shall also be 0.
        The format of the data bytes is shown in Table 11.

        Args:
            group_id (int): A group identification number (4 bits)
            gnum (int): The number of units in the group (4 bits) and
            iorder (int): The interleave order for this particular unit (4
            bits). This number ranges in value from zero to one less than
            the number of units in the group.

        Returns:
            group_id (int): A group identification number (4 bits), 1 byte,
            unsigned
            gnum (int): The number of units in the group (4 bits) and, 1 byte,
            unsigned
            iorder (int): The interleave order for this particular unit (4
            bits), 1 byte, unsigned
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        dowrite = False
        group_id = 0x00
        gnum = 0x00
        iorder = 0x00

        if 'group_id' in kwargs:
            dowrite = True
            group_id = kwargs['group_id']
            del kwargs['group_id']
        if 'gnum' in kwargs:
            dowrite = True
            gnum = kwargs['gnum']
            del kwargs['gnum']
        if 'iorder' in kwargs:
            dowrite = True
            iorder = kwargs['iorder']
            del kwargs['iorder']
        if dowrite:
            assembly = (((group_id & 0x0F) << 8) | ((gnum & 0x0F) << 4) |
                        (iorder & 0x0F))
            interleavebytes = assembly.to_bytes(2, byteorder='little',
                                                signed=False)
            self.write_slave([self.commands.interleave, interleavebytes],
                             **kwargs)
            return None
        else:
            response = self.query_slave([self.commands.interleave], 2,
                                        **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        group_id = (response & 0x0F00) >> 8
        gnum = (response & 0x00F0) >> 4
        iorder = (response & 0x000F)
        return (group_id, gnum, iorder)

    def get_iout_cal_gain(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.iout_cal_gain,
                                  byteorder='little', signed=False, **kwargs)

    def set_iout_cal_gain(self, cal_gain: int, **kwargs) -> None:
        self.set_pmbus_two(cal_gain, self.commands.iout_cal_gain,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def iout_cal_gain(self):
        """
        iout_cal_gain()

        reads back the iout_cal_gain currently set in the slave device
        if duty is provided will set the iout_cal_gain

        Args:
            duty (int): if provided will set the iout_cal_gain

        Returns:
            int: iout_cal_gain set in slave, unsigned, 2 byte
        """
        self._iout_cal_gain = self.get_iout_cal_gain()
        return self._iout_cal_gain

    @iout_cal_gain.setter
    def iout_cal_gain(self, cal_gain: int) -> None:
        self.set_iout_cal_gain(cal_gain)
        return None

    def get_iout_cal_offset(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.iout_cal_offset,
                                  byteorder='little', signed=False, **kwargs)

    def set_iout_cal_offset(self, cal_offset: int, **kwargs) -> None:
        self.set_pmbus_two(cal_offset, self.commands.iout_cal_offset,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def iout_cal_offset(self):
        """
        iout_cal_offset()

        reads back the iout_cal_offset currently set in the slave device
        if duty is provided will set the iout_cal_offset

        Args:
            duty (int): if provided will set the iout_cal_offset

        Returns:
            int: iout_cal_offset set in slave, unsigned, 2 byte
        """
        self._iout_cal_offset = self.get_iout_cal_offset()
        return self._iout_cal_offset

    @iout_cal_offset.setter
    def iout_cal_offset(self, cal_offset: int) -> None:
        self.set_iout_cal_offset(cal_offset)
        return None

    def fan_config_1_2(self, **kwargs):
        """
        fan_config_1_2()

        reads back the fan_config_1_2 currently set in the slave device
        if fan1 is provided will set the fan1 existance to True
        if fan1_mode is provided will set the fan1_mode to RPM/Duty
        if fan1_tach is provided will set the fan1 pulses per revolution
        if fan2 is provided will set the fan2 existance to True
        if fan2_mode is provided will set the fan2_mode to RPM/Duty
        if fan2_tach is provided will set the fan2 pulses per revolution

        Args:
            fan1 (bool): fan1 "present" True
            fan2 (bool): fan2 "present" True
            fan1_mode (bool): fan1 RPM mode True, Duty Cycle mode False
            fan2_mode (bool): fan2 RPM mode True, Duty Cycle mode False
            fan1_tach (int): if provided will set fan1_tach ppr
            fan2_tach (int): if provided will set fan1_tach ppr

        Returns:
            fan1 (bool): fan1 present
            fan2 (bool): fan2 present
            fan1_mode (bool): fan1 RPM mode True, Duty Cycle mode False
            fan2_mode (bool): fan2 RPM mode True, Duty Cycle mode False
            fan1_tach (int): fan1_tach ppr, 1 byte, unsigned
            fan2_tach (int): fan1_tach ppr, 1 byte, unsigned

        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        dowrite = False
        fan1 = True
        fan2 = True
        fan1_mode = True
        fan2_mode = True
        fan1_tach = 0x00  # default to make it fastest! 0 = 1
        fan2_tach = 0x00  # default to make it fastest! 0 = 1

        if 'fan1' in kwargs:
            dowrite = True
            fan1 = kwargs['fan1']
            del kwargs['fan1']
        if 'fan2' in kwargs:
            dowrite = True
            fan2 = kwargs['fan2']
            del kwargs['fan2']
        if 'fan1_mode' in kwargs:
            dowrite = True
            fan1_mode = kwargs['fan1_mode']
            del kwargs['fan1_mode']
        if 'fan2_mode' in kwargs:
            dowrite = True
            fan2_mode = kwargs['fan2_mode']
            del kwargs['fan2_mode']
        if 'fan1_tach' in kwargs:
            dowrite = True
            fan1_tach = kwargs['fan1_tach']
            del kwargs['fan1_tach']
        if 'fan2_tach' in kwargs:
            dowrite = True
            fan2_tach = kwargs['fan2_tach']
            del kwargs['fan2_tach']
        if dowrite:
            assembly = (((fan1 & 0x01) << 7) | ((fan1_mode & 0x01) << 6) |
                        ((fan1_tach & 0x03) << 4) | ((fan2 & 0x01) << 3) |
                        ((fan2_mode & 0x01) << 2) | (fan2_tach & 0x03))
            self.write_slave([self.commands.fan_config_1_2, int(assembly)],
                             **kwargs)
            return None
        else:
            response = self.query_slave([self.commands.fan_config_1_2], 1,
                                        **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        fan1 = (response & (0x01 << 7)) >> 7
        fan1_mode = (response & (0x01 << 6)) >> 6
        fan1_tach = (response & (0x03 << 4)) >> 4
        fan2 = (response & (0x01 << 3)) >> 3
        fan2_mode = (response & (0x01 << 2)) >> 2
        fan2_tach = (response & (0x03))
        return (fan1, fan1_mode, fan1_tach, fan2, fan2_mode, fan2_tach)

    def fan_config_3_4(self, **kwargs):
        """
        fan_config_3_4()

        reads back the fan_config_3_4 currently set in the slave device
        if fan3 is provided will set the fan3 existance to True
        if fan3_mode is provided will set the fan3_mode to RPM/Duty
        if fan3_tach is provided will set the fan3 pulses per revolution
        if fan4 is provided will set the fan4 existance to True
        if fan4_mode is provided will set the fan4_mode to RPM/Duty
        if fan4_tach is provided will set the fan4 pulses per revolution

        Args:
            fan3 (bool): fan3 "present" True
            fan4 (bool): fan4 "present" True
            fan3_mode (bool): fan3 RPM mode True, Duty Cycle mode False
            fan4_mode (bool): fan4 RPM mode True, Duty Cycle mode False
            fan3_tach (int): if provided will set fan3_tach ppr
            fan4_tach (int): if provided will set fan3_tach ppr

        Returns:
            fan3 (bool): fan3 present
            fan4 (bool): fan4 present
            fan3_mode (bool): fan3 RPM mode True, Duty Cycle mode False
            fan4_mode (bool): fan4 RPM mode True, Duty Cycle mode False
            fan3_tach (int): fan3_tach ppr, 1 byte, unsigned
            fan4_tach (int): fan3_tach ppr, 1 byte, unsigned

        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        dowrite = False
        fan3 = True
        fan4 = True
        fan3_mode = True
        fan4_mode = True
        fan3_tach = 0x00  # default to make it fastest! 0 = 1
        fan4_tach = 0x00  # default to make it fastest! 0 = 1

        if 'fan3' in kwargs:
            dowrite = True
            fan3 = kwargs['fan3']
            del kwargs['fan3']
        if 'fan4' in kwargs:
            dowrite = True
            fan4 = kwargs['fan4']
            del kwargs['fan4']
        if 'fan3_mode' in kwargs:
            dowrite = True
            fan3_mode = kwargs['fan3_mode']
            del kwargs['fan3_mode']
        if 'fan4_mode' in kwargs:
            dowrite = True
            fan4_mode = kwargs['fan4_mode']
            del kwargs['fan4_mode']
        if 'fan3_tach' in kwargs:
            dowrite = True
            fan3_tach = kwargs['fan3_tach']
            del kwargs['fan3_tach']
        if 'fan4_tach' in kwargs:
            dowrite = True
            fan4_tach = kwargs['fan4_tach']
            del kwargs['fan4_tach']
        if dowrite:
            assembly = (((fan3 & 0x01) << 7) | ((fan3_mode & 0x01) << 6) |
                        ((fan3_tach & 0x03) << 4) | ((fan4 & 0x01) << 3) |
                        ((fan4_mode & 0x01) << 2) | (fan4_tach & 0x03))
            self.write_slave([self.commands.fan_config_3_4, int(assembly)],
                             **kwargs)
            return None
        else:
            response = self.query_slave([self.commands.fan_config_3_4], 1,
                                        **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        fan3 = (response & (0x01 << 7)) >> 7
        fan3_mode = (response & (0x01 << 6)) >> 6
        fan3_tach = (response & (0x03 << 4)) >> 4
        fan4 = (response & (0x01 << 3)) >> 3
        fan4_mode = (response & (0x01 << 2)) >> 2
        fan4_tach = (response & (0x03))
        return (fan3, fan3_mode, fan3_tach, fan4, fan4_mode, fan4_tach)

    def get_fan_command_1(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.fan_command_1,
                                  byteorder='little', signed=False, **kwargs)

    def set_fan_command_1(self, command: int, **kwargs) -> None:
        self.set_pmbus_two(command, self.commands.fan_command_1,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def fan_command_1(self):
        """
        fan_command_1()

        reads back the fan_command_1 currently set in the slave device
        if duty is provided will set the fan_command_1

        Args:
            duty (int): if provided will set the fan_command_1

        Returns:
            int: fan_command_1 set in slave, unsigned, 2 byte
        """
        self._fan_command_1 = self.get_fan_command_1()
        return self._fan_command_1

    @fan_command_1.setter
    def fan_command_1(self, command: int) -> None:
        self.set_fan_command_1(command)
        return None

    def get_fan_command_2(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.fan_command_2,
                                  byteorder='little', signed=False, **kwargs)

    def set_fan_command_2(self, command: int, **kwargs) -> None:
        self.set_pmbus_two(command, self.commands.fan_command_2,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def fan_command_2(self):
        """
        fan_command_2()

        reads back the fan_command_2 currently set in the slave device
        if duty is provided will set the fan_command_2

        Args:
            duty (int): if provided will set the fan_command_2

        Returns:
            int: fan_command_2 set in slave, unsigned, 2 byte
        """
        self._fan_command_2 = self.get_fan_command_2()
        return self._fan_command_2

    @fan_command_2.setter
    def fan_command_2(self, command: int) -> None:
        self.set_fan_command_2(command)
        return None

    def get_fan_command_3(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.fan_command_3,
                                  byteorder='little', signed=False, **kwargs)

    def set_fan_command_3(self, command: int, **kwargs) -> None:
        self.set_pmbus_two(command, self.commands.fan_command_3,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def fan_command_3(self):
        """
        fan_command_3()

        reads back the fan_command_3 currently set in the slave device
        if duty is provided will set the fan_command_3

        Args:
            duty (int): if provided will set the fan_command_3

        Returns:
            int: fan_command_3 set in slave, unsigned, 2 byte
        """
        self._fan_command_3 = self.get_fan_command_3()
        return self._fan_command_3

    @fan_command_3.setter
    def fan_command_3(self, command: int) -> None:
        self.set_fan_command_3(command)
        return None

    def get_fan_command_4(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.fan_command_4,
                                  byteorder='little', signed=False, **kwargs)

    def set_fan_command_4(self, command: int, **kwargs) -> None:
        self.set_pmbus_two(command, self.commands.fan_command_4,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def fan_command_4(self):
        """
        fan_command_4()

        reads back the fan_command_4 currently set in the slave device
        if duty is provided will set the fan_command_4

        Args:
            duty (int): if provided will set the fan_command_4

        Returns:
            int: fan_command_4 set in slave, unsigned, 2 byte
        """
        self._fan_command_4 = self.get_fan_command_4()
        return self._fan_command_4

    @fan_command_4.setter
    def fan_command_4(self, command: int) -> None:
        self.set_fan_command_4(command)
        return None

    def get_vout_ov_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_ov_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_ov_fault_limit(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_ov_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_ov_fault_limit(self):
        """
        vout_ov_fault_limit()

        reads back the vout_ov_fault_limit currently set in the slave device
        if duty is provided will set the vout_ov_fault_limit

        Args:
            duty (int): if provided will set the vout_ov_fault_limit

        Returns:
            int: vout_ov_fault_limit set in slave, unsigned, 2 byte
        """
        self._vout_ov_fault_limit = self.get_vout_ov_fault_limit()
        return self._vout_ov_fault_limit

    @vout_ov_fault_limit.setter
    def vout_ov_fault_limit(self, vout: int) -> None:
        self.set_vout_ov_fault_limit(vout)
        return None

    def get_vout_ov_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.vout_ov_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_vout_ov_fault_response(self, response: int, retry: int, delay: int,
                                   **kwargs) -> None:
        cmd = self.commands.vout_ov_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def vout_ov_fault_response(self) -> "tuple(int, int, int)":
        """
        vout_ov_fault_response()

        reads back the vout_ov_fault_response currently set in the slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._vout_ov_fault_response = self.get_vout_ov_fault_response()
        return self._vout_ov_fault_response

    @vout_ov_fault_response.setter
    def vout_ov_fault_response(self, response) -> None:
        self.set_vout_ov_fault_response(response[0], response[1], response[2])
        return None

    def get_vout_ov_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_ov_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_ov_warn_limit(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_ov_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_ov_warn_limit(self):
        """
        vout_ov_warn_limit()

        reads back the vout_ov_warn_limit currently set in the slave device
        if duty is provided will set the vout_ov_warn_limit

        Args:
            duty (int): if provided will set the vout_ov_warn_limit

        Returns:
            int: vout_ov_warn_limit set in slave, unsigned, 2 byte
        """
        self._vout_ov_warn_limit = self.get_vout_ov_warn_limit()
        return self._vout_ov_warn_limit

    @vout_ov_warn_limit.setter
    def vout_ov_warn_limit(self, vout: int) -> None:
        self.set_vout_ov_warn_limit(vout)
        return None

    def get_vout_uv_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vout_uv_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_vout_uv_warn_limit(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.vout_uv_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vout_uv_warn_limit(self):
        """
        vout_uv_warn_limit()

        reads back the vout_uv_warn_limit currently set in the slave device
        if duty is provided will set the vout_uv_warn_limit

        Args:
            duty (int): if provided will set the vout_uv_warn_limit

        Returns:
            int: vout_uv_warn_limit set in slave, unsigned, 2 byte
        """
        self._vout_uv_warn_limit = self.get_vout_uv_warn_limit()
        return self._vout_uv_warn_limit

    @vout_uv_warn_limit.setter
    def vout_uv_warn_limit(self, vout: int) -> None:
        self.set_vout_uv_warn_limit(vout)
        return None

    def get_vout_uv_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.vout_uv_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_vout_uv_fault_response(self, response: int, retry: int, delay: int,
                                   **kwargs) -> None:
        cmd = self.commands.vout_uv_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def vout_uv_fault_response(self) -> "tuple(int, int, int)":
        """
        vout_uv_fault_response()

        reads back the vout_uv_fault_response currently set in the slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._vout_uv_fault_response = self.get_vout_uv_fault_response()
        return self._vout_uv_fault_response

    @vout_uv_fault_response.setter
    def vout_uv_fault_response(self, response) -> None:
        self.set_vout_uv_fault_response(response[0], response[1], response[2])
        return None

    def get_iout_oc_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.iout_oc_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_iout_oc_fault_limit(self, iout: int, **kwargs) -> None:
        self.set_pmbus_two(iout, self.commands.iout_oc_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def iout_oc_fault_limit(self):
        """
        iout_oc_fault_limit()

        reads back the iout_oc_fault_limit currently set in the slave device
        if duty is provided will set the iout_oc_fault_limit

        Args:
            duty (int): if provided will set the iout_oc_fault_limit

        Returns:
            int: iout_oc_fault_limit set in slave, unsigned, 2 byte
        """
        self._iout_oc_fault_limit = self.get_iout_oc_fault_limit()
        return self._iout_oc_fault_limit

    @iout_oc_fault_limit.setter
    def iout_oc_fault_limit(self, iout: int) -> None:
        self.set_iout_oc_fault_limit(iout)
        return None

    def get_iout_oc_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.iout_oc_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_iout_oc_fault_response(self, response: int, retry: int, delay: int,
                                   **kwargs) -> None:
        cmd = self.commands.iout_oc_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def iout_oc_fault_response(self) -> "tuple(int, int, int)":
        """
        iout_oc_fault_response()

        reads back the iout_oc_fault_response currently set in the slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._iout_oc_fault_response = self.get_iout_oc_fault_response()
        return self._iout_oc_fault_response

    @iout_oc_fault_response.setter
    def iout_oc_fault_response(self, response) -> None:
        self.set_iout_oc_fault_response(response[0], response[1], response[2])
        return None

    def get_iout_oc_lv_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.iout_oc_lv_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_iout_oc_lv_fault_limit(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.iout_oc_lv_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def iout_oc_lv_fault_limit(self):
        """
        iout_oc_lv_fault_limit()

        reads back the iout_oc_lv_fault_limit currently set in the slave device
        if vout is provided will set the iout_oc_lv_fault_limit

        Args:
            vout (int): if provided will set the iout_oc_lv_fault_limit

        Returns:
            int: iout_oc_lv_fault_limit set in slave, unsigned, 2 byte
        """
        self._iout_oc_lv_fault_limit = self.get_iout_oc_lv_fault_limit()
        return self._iout_oc_lv_fault_limit

    @iout_oc_lv_fault_limit.setter
    def iout_oc_lv_fault_limit(self, vout: int) -> None:
        self.set_iout_oc_lv_fault_limit(vout)
        return None

    def get_iout_oc_lv_fault_response(self,
                                      **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.iout_oc_lv_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_iout_oc_lv_fault_response(self, response: int, retry: int,
                                      delay: int, **kwargs) -> None:
        cmd = self.commands.iout_oc_lv_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def iout_oc_lv_fault_response(self) -> "tuple(int, int, int)":
        """
        iout_oc_lv_fault_response()

        reads back the iout_oc_lv_fault_response currently set in the slave
        device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._iout_oc_lv_fault_response = self.get_iout_oc_lv_fault_response()
        return self._iout_oc_lv_fault_response

    @iout_oc_lv_fault_response.setter
    def iout_oc_lv_fault_response(self, response) -> None:
        self.set_iout_oc_lv_fault_response(response[0], response[1],
                                           response[2])
        return None

    def get_iout_oc_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.iout_oc_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_iout_oc_warn_limit(self, iout: int, **kwargs) -> None:
        self.set_pmbus_two(iout, self.commands.iout_oc_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def iout_oc_warn_limit(self):
        """
        iout_oc_warn_limit()

        reads back the iout_oc_warn_limit currently set in the slave device
        if iout is provided will set the iout_oc_warn_limit

        Args:
            iout (int): if provided will set the iout_oc_warn_limit

        Returns:
            int: iout_oc_warn_limit set in slave, unsigned, 2 byte
        """
        self._iout_oc_warn_limit = self.get_iout_oc_warn_limit()
        return self._iout_oc_warn_limit

    @iout_oc_warn_limit.setter
    def iout_oc_warn_limit(self, iout: int) -> None:
        self.set_iout_oc_warn_limit(iout)
        return None

    def get_iout_uc_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.iout_uc_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_iout_uc_fault_limit(self, iout: int, **kwargs) -> None:
        self.set_pmbus_two(iout, self.commands.iout_uc_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def iout_uc_fault_limit(self):
        """
        iout_uc_fault_limit()

        reads back the iout_uc_fault_limit currently set in the slave device
        if iout is provided will set the iout_uc_fault_limit

        Args:
            iout (int): if provided will set the iout_uc_fault_limit

        Returns:
            int: iout_uc_fault_limit set in slave, unsigned, 2 byte
        """
        self._iout_uc_fault_limit = self.get_iout_uc_fault_limit()
        return self._iout_uc_fault_limit

    @iout_uc_fault_limit.setter
    def iout_uc_fault_limit(self, iout: int) -> None:
        self.set_iout_uc_fault_limit(iout)
        return None

    def get_iout_uc_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.iout_uc_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_iout_uc_fault_response(self, response: int, retry: int, delay: int,
                                   **kwargs) -> None:
        cmd = self.commands.iout_uc_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def iout_uc_fault_response(self) -> "tuple(int, int, int)":
        """
        iout_uc_fault_response()

        reads back the iout_uc_fault_response currently set in the
        slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._iout_uc_fault_response = self.get_iout_uc_fault_response()
        return self._iout_uc_fault_response

    @iout_uc_fault_response.setter
    def iout_uc_fault_response(self, response) -> None:
        self.set_iout_uc_fault_response(response[0], response[1], response[2])
        return None

    def get_ot_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.ot_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_ot_fault_limit(self, temp: int, **kwargs) -> None:
        self.set_pmbus_two(temp, self.commands.ot_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def ot_fault_limit(self):
        """
        ot_fault_limit()

        reads back the ot_fault_limit currently set in the slave device
        if temp is provided will set the ot_fault_limit

        Args:
            temp (int): if provided will set the ot_fault_limit

        Returns:
            int: ot_fault_limit set in slave, unsigned, 2 byte
        """
        self._ot_fault_limit = self.get_ot_fault_limit()
        return self._ot_fault_limit

    @ot_fault_limit.setter
    def ot_fault_limit(self, temp: int) -> None:
        self.set_ot_fault_limit(temp)
        return None

    def get_ot_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.ot_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_ot_fault_response(self, response: int, retry: int,
                              delay: int, **kwargs) -> None:
        cmd = self.commands.ot_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def ot_fault_response(self) -> "tuple(int, int, int)":
        """
        ot_fault_response()

        reads back the ot_fault_response currently set in the
        slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._ot_fault_response = self.get_ot_fault_response()
        return self._ot_fault_response

    @ot_fault_response.setter
    def ot_fault_response(self, response) -> None:
        self.set_ot_fault_response(response[0], response[1], response[2])
        return None

    def get_ot_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.ot_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_ot_warn_limit(self, temp: int, **kwargs) -> None:
        self.set_pmbus_two(temp, self.commands.ot_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def ot_warn_limit(self):
        """
        ot_warn_limit()

        reads back the ot_warn_limit currently set in the slave device
        if temp is provided will set the ot_warn_limit

        Args:
            temp (int): if provided will set the ot_warn_limit

        Returns:
            int: ot_warn_limit set in slave, unsigned, 2 byte
        """
        self._ot_warn_limit = self.get_ot_warn_limit()
        return self._ot_warn_limit

    @ot_warn_limit.setter
    def ot_warn_limit(self, temp: int) -> None:
        self.set_ot_warn_limit(temp)
        return None

    def get_ut_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.ut_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_ut_warn_limit(self, temp: int, **kwargs) -> None:
        self.set_pmbus_two(temp, self.commands.ut_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def ut_warn_limit(self):
        """
        ut_warn_limit()

        reads back the ut_warn_limit currently set in the slave device
        if temp is provided will set the ut_warn_limit

        Args:
            temp (int): if provided will set the ut_warn_limit

        Returns:
            int: ut_warn_limit set in slave, unsigned, 2 byte
        """
        self._ut_warn_limit = self.get_ut_warn_limit()
        return self._ut_warn_limit

    @ut_warn_limit.setter
    def ut_warn_limit(self, temp: int) -> None:
        self.set_ut_warn_limit(temp)
        return None

    def get_ut_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.ut_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_ut_fault_limit(self, temp: int, **kwargs) -> None:
        self.set_pmbus_two(temp, self.commands.ut_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def ut_fault_limit(self):
        """
        ut_fault_limit()

        reads back the ut_fault_limit currently set in the slave device
        if temp is provided will set the ut_fault_limit

        Args:
            temp (int): if provided will set the ut_fault_limit

        Returns:
            int: ut_fault_limit set in slave, unsigned, 2 byte
        """
        self._ut_fault_limit = self.get_ut_fault_limit()
        return self._ut_fault_limit

    @ut_fault_limit.setter
    def ut_fault_limit(self, temp: int) -> None:
        self.set_ut_fault_limit(temp)
        return None

    def get_ut_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.ut_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_ut_fault_response(self, response: int, retry: int,
                              delay: int, **kwargs) -> None:
        cmd = self.commands.ut_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def ut_fault_response(self) -> "tuple(int, int, int)":
        """
        ut_fault_response()

        reads back the ut_fault_response currently set in the
        slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._ut_fault_response = self.get_ut_fault_response()
        return self._ut_fault_response

    @ut_fault_response.setter
    def ut_fault_response(self, response) -> None:
        self.set_ut_fault_response(response[0], response[1], response[2])
        return None

    def get_vin_ov_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vin_ov_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_vin_ov_fault_limit(self, vin: int, **kwargs) -> None:
        self.set_pmbus_two(vin, self.commands.vin_ov_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vin_ov_fault_limit(self):
        """
        vin_ov_fault_limit()

        reads back the vin_ov_fault_limit currently set in the slave device
        if vin is provided will set the vin_ov_fault_limit

        Args:
            vin (int): if provided will set the vin_ov_fault_limit

        Returns:
            int: vin_ov_fault_limit set in slave, unsigned, 2 byte
        """
        self._vin_ov_fault_limit = self.get_vin_ov_fault_limit()
        return self._vin_ov_fault_limit

    @vin_ov_fault_limit.setter
    def vin_ov_fault_limit(self, vin: int) -> None:
        self.set_vin_ov_fault_limit(vin)
        return None

    def get_vin_ov_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.vin_ov_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_vin_ov_fault_response(self, response: int, retry: int,
                                  delay: int, **kwargs) -> None:
        cmd = self.commands.vin_ov_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def vin_ov_fault_response(self) -> "tuple(int, int, int)":
        """
        vin_ov_fault_response()

        reads back the vin_ov_fault_response currently set in the
        slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._vin_ov_fault_response = self.get_vin_ov_fault_response()
        return self._vin_ov_fault_response

    @vin_ov_fault_response.setter
    def vin_ov_fault_response(self, response) -> None:
        self.set_vin_ov_fault_response(response[0], response[1], response[2])
        return None

    def get_vin_ov_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vin_ov_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_vin_ov_warn_limit(self, vin: int, **kwargs) -> None:
        self.set_pmbus_two(vin, self.commands.vin_ov_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vin_ov_warn_limit(self):
        """
        vin_ov_warn_limit()

        reads back the vin_ov_warn_limit currently set in the slave device
        if vin is provided will set the vin_ov_warn_limit

        Args:
            vin (int): if provided will set the vin_ov_warn_limit

        Returns:
            int: vin_ov_warn_limit set in slave, unsigned, 2 byte
        """
        self._vin_ov_warn_limit = self.get_vin_ov_warn_limit()
        return self._vin_ov_warn_limit

    @vin_ov_warn_limit.setter
    def vin_ov_warn_limit(self, vin: int) -> None:
        self.set_vin_ov_warn_limit(vin)
        return None

    def get_vin_uv_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vin_uv_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_vin_uv_warn_limit(self, vin: int, **kwargs) -> None:
        self.set_pmbus_two(vin, self.commands.vin_uv_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vin_uv_warn_limit(self):
        """
        vin_uv_warn_limit()

        reads back the vin_uv_warn_limit currently set in the slave device
        if vin is provided will set the vin_uv_warn_limit

        Args:
            vin (int): if provided will set the vin_uv_warn_limit

        Returns:
            int: vin_uv_warn_limit set in slave, unsigned, 2 byte
        """
        self._vin_uv_warn_limit = self.get_vin_uv_warn_limit()
        return self._vin_uv_warn_limit

    @vin_uv_warn_limit.setter
    def vin_uv_warn_limit(self, vin: int) -> None:
        self.set_vin_uv_warn_limit(vin)
        return None

    def get_vin_uv_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.vin_uv_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_vin_uv_fault_limit(self, vin: int, **kwargs) -> None:
        self.set_pmbus_two(vin, self.commands.vin_uv_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def vin_uv_fault_limit(self):
        """
        vin_uv_fault_limit()

        reads back the vin_uv_fault_limit currently set in the slave device
        if vin is provided will set the vin_uv_fault_limit

        Args:
            vin (int): if provided will set the vin_uv_fault_limit

        Returns:
            int: vin_uv_fault_limit set in slave, unsigned, 2 byte
        """
        self._vin_uv_fault_limit = self.get_vin_uv_fault_limit()
        return self._vin_uv_fault_limit

    @vin_uv_fault_limit.setter
    def vin_uv_fault_limit(self, vin: int) -> None:
        self.set_vin_uv_fault_limit(vin)
        return None

    def get_vin_uv_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.vin_uv_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_vin_uv_fault_response(self, response: int, retry: int,
                                  delay: int, **kwargs) -> None:
        cmd = self.commands.vin_uv_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def vin_uv_fault_response(self) -> "tuple(int, int, int)":
        """
        vin_uv_fault_response()

        reads back the vin_uv_fault_response currently set in the
        slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._vin_uv_fault_response = self.get_vin_uv_fault_response()
        return self._vin_uv_fault_response

    @vin_uv_fault_response.setter
    def vin_uv_fault_response(self, response) -> None:
        self.set_vin_uv_fault_response(response[0], response[1], response[2])
        return None

    def get_iin_oc_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.iin_oc_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_iin_oc_fault_limit(self, iin: int, **kwargs) -> None:
        self.set_pmbus_two(iin, self.commands.iin_oc_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def iin_oc_fault_limit(self):
        """
        iin_oc_fault_limit()

        reads back the iin_oc_fault_limit currently set in the slave device
        if iin is provided will set the iin_oc_fault_limit

        Args:
            iin (int): if provided will set the iin_oc_fault_limit

        Returns:
            int: iin_oc_fault_limit set in slave, unsigned, 2 byte
        """
        self._iin_oc_fault_limit = self.get_iin_oc_fault_limit()
        return self._iin_oc_fault_limit

    @iin_oc_fault_limit.setter
    def iin_oc_fault_limit(self, iin: int) -> None:
        self.set_iin_oc_fault_limit(iin)
        return None

    def get_iin_oc_fault_response(self, **kwargs) -> "tuple(int, int, int)":
        cmd = self.commands.iin_oc_fault_response
        return self.fault_response(cmd, None, None, None, True, **kwargs)

    def set_iin_oc_fault_response(self, response: int, retry: int,
                                  delay: int, **kwargs) -> None:
        cmd = self.commands.iin_oc_fault_response
        self.fault_response(cmd, response, retry, delay, False, **kwargs)
        return None

    @property
    def iin_oc_fault_response(self) -> "tuple(int, int, int)":
        """
        iin_oc_fault_response()

        reads back the iin_oc_fault_response currently set in the
        slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            tuple(response, retry, delay)
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        self._iin_oc_fault_response = self.get_iin_oc_fault_response()
        return self._iin_oc_fault_response

    @iin_oc_fault_response.setter
    def iin_oc_fault_response(self, response) -> None:
        self.set_iin_oc_fault_response(response[0], response[1], response[2])
        return None

    def get_iin_oc_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.iin_oc_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_iin_oc_warn_limit(self, iin: int, **kwargs) -> None:
        self.set_pmbus_two(iin, self.commands.iin_oc_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def iin_oc_warn_limit(self):
        """
        iin_oc_warn_limit()

        reads back the iin_oc_warn_limit currently set in the slave device
        if iin is provided will set the iin_oc_warn_limit

        Args:
            iin (int): if provided will set the iin_oc_warn_limit

        Returns:
            int: iin_oc_warn_limit set in slave, unsigned, 2 byte
        """
        self._iin_oc_warn_limit = self.get_iin_oc_warn_limit()
        return self._iin_oc_warn_limit

    @iin_oc_warn_limit.setter
    def iin_oc_warn_limit(self, iin: int) -> None:
        self.set_iin_oc_warn_limit(iin)
        return None

    def get_power_good_on(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.power_good_on,
                                  byteorder='little', signed=False, **kwargs)

    def set_power_good_on(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.power_good_on,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def power_good_on(self):
        """
        power_good_on()

        reads back the power_good_on currently set in the slave device
        if vout is provided will set the power_good_on

        Args:
            vout (int): if provided will set the power_good_on

        Returns:
            int: power_good_on set in slave, unsigned, 2 byte
        """
        self._power_good_on = self.get_power_good_on()
        return self._power_good_on

    @power_good_on.setter
    def power_good_on(self, vout: int) -> None:
        self.set_power_good_on(vout)
        return None

    def get_power_good_off(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.power_good_off,
                                  byteorder='little', signed=False, **kwargs)

    def set_power_good_off(self, vout: int, **kwargs) -> None:
        self.set_pmbus_two(vout, self.commands.power_good_off,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def power_good_off(self):
        """
        power_good_off()

        reads back the power_good_off currently set in the slave device
        if vout is provided will set the power_good_off

        Args:
            vout (int): if provided will set the power_good_off

        Returns:
            int: power_good_off set in slave, unsigned, 2 byte
        """
        self._power_good_off = self.get_power_good_off()
        return self._power_good_off

    @power_good_off.setter
    def power_good_off(self, vout: int) -> None:
        self.set_power_good_off(vout)
        return None

    def get_ton_delay(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.ton_delay,
                                  byteorder='little', signed=False, **kwargs)

    def set_ton_delay(self, delay: int, **kwargs) -> None:
        self.set_pmbus_two(delay, self.commands.ton_delay,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def ton_delay(self):
        """
        ton_delay()

        reads back the ton_delay currently set in the slave device
        if delay is provided will set the ton_delay

        Args:
            delay (int): if provided will set the ton_delay

        Returns:
            int: ton_delay set in slave, unsigned, 2 byte
        """
        self._ton_delay = self.get_ton_delay()
        return self._ton_delay

    @ton_delay.setter
    def ton_delay(self, delay: int) -> None:
        self.set_ton_delay(delay)
        return None

    def get_ton_rise(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.ton_rise,
                                  byteorder='little', signed=False, **kwargs)

    def set_ton_rise(self, rise: int, **kwargs) -> None:
        self.set_pmbus_two(rise, self.commands.ton_rise,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def ton_rise(self):
        """
        ton_rise()

        reads back the ton_rise currently set in the slave device
        if rise is provided will set the ton_rise

        Args:
            rise (int): if provided will set the ton_rise

        Returns:
            int: ton_rise set in slave, unsigned, 2 byte
        """
        self._ton_rise = self.get_ton_rise()
        return self._ton_rise

    @ton_rise.setter
    def ton_rise(self, rise: int) -> None:
        self.set_ton_rise(rise)
        return None

    def get_ton_max_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.ton_max_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_ton_max_fault_limit(self, ton: int, **kwargs) -> None:
        self.set_pmbus_two(ton, self.commands.ton_max_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def ton_max_fault_limit(self):
        """
        ton_max_fault_limit()

        reads back the ton_max_fault_limit currently set in the slave device
        if ton is provided will set the ton_max_fault_limit

        Args:
            ton (int): if provided will set the ton_max_fault_limit

        Returns:
            int: ton_max_fault_limit set in slave, unsigned, 2 byte
        """
        self._ton_max_fault_limit = self.get_ton_max_fault_limit()
        return self._ton_max_fault_limit

    @ton_max_fault_limit.setter
    def ton_max_fault_limit(self, ton: int) -> None:
        self.set_ton_max_fault_limit(ton)
        return None

    def ton_max_fault_response(self, response=None, retry=None, delay=None,
                               doRead=False, **kwargs):
        """
        ton_max_fault_response()

        reads back the ton_max_fault_response currently set in the slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        cmd = self.commands.ton_max_fault_response

        return self.fault_response(cmd, response, retry, delay, doRead,
                                   **kwargs)

    def get_toff_delay(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.toff_delay,
                                  byteorder='little', signed=False, **kwargs)

    def set_toff_delay(self, delay: int, **kwargs) -> None:
        self.set_pmbus_two(delay, self.commands.toff_delay,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def toff_delay(self):
        """
        toff_delay()

        reads back the toff_delay currently set in the slave device
        if delay is provided will set the toff_delay

        Args:
            delay (int): if provided will set the toff_delay

        Returns:
            int: toff_delay set in slave, unsigned, 2 byte
        """
        self._toff_delay = self.get_toff_delay()
        return self._toff_delay

    @toff_delay.setter
    def toff_delay(self, delay: int) -> None:
        self.set_toff_delay(delay)
        return None

    def get_toff_fall(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.toff_fall,
                                  byteorder='little', signed=False, **kwargs)

    def set_toff_fall(self, fall: int, **kwargs) -> None:
        self.set_pmbus_two(fall, self.commands.toff_fall,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def toff_fall(self):
        """
        toff_fall()

        reads back the toff_fall currently set in the slave device
        if fall is provided will set the toff_fall

        Args:
            fall (int): if provided will set the toff_fall

        Returns:
            int: toff_fall set in slave, unsigned, 2 byte
        """
        self._toff_fall = self.get_toff_fall()
        return self._toff_fall

    @toff_fall.setter
    def toff_fall(self, fall: int) -> None:
        self.set_toff_fall(fall)
        return None

    def get_toff_max_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.toff_max_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_toff_max_warn_limit(self, toff: int, **kwargs) -> None:
        self.set_pmbus_two(toff, self.commands.toff_max_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def toff_max_warn_limit(self):
        """
        toff_max_warn_limit()

        reads back the toff_max_warn_limit currently set in the slave device
        if toff is provided will set the toff_max_warn_limit

        Args:
            toff (int): if provided will set the toff_max_warn_limit

        Returns:
            int: toff_max_warn_limit set in slave, unsigned, 2 byte
        """
        self._toff_max_warn_limit = self.get_toff_max_warn_limit()
        return self._toff_max_warn_limit

    @toff_max_warn_limit.setter
    def toff_max_warn_limit(self, toff: int) -> None:
        self.set_toff_max_warn_limit(toff)
        return None

    def get_pout_op_fault_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.pout_op_fault_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_pout_op_fault_limit(self, pout: int, **kwargs) -> None:
        self.set_pmbus_two(pout, self.commands.pout_op_fault_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def pout_op_fault_limit(self):
        """
        pout_op_fault_limit()

        reads back the pout_op_fault_limit currently set in the slave device
        if pout is provided will set the pout_op_fault_limit

        Args:
            pout (int): if provided will set the pout_op_fault_limit

        Returns:
            int: pout_op_fault_limit set in slave, unsigned, 2 byte
        """
        self._pout_op_fault_limit = self.get_pout_op_fault_limit()
        return self._pout_op_fault_limit

    @pout_op_fault_limit.setter
    def pout_op_fault_limit(self, pout: int) -> None:
        self.set_pout_op_fault_limit(pout)
        return None

    def pout_op_fault_response(self, response=None, retry=None, delay=None,
                               doRead=False, **kwargs):
        """
        pout_op_fault_response()

        reads back the pout_op_fault_response currently set in the slave device
        if response provided will set the response
        if retry provided will set the retry
        if delay provided will set the delay

        Args:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        Returns:
            response (int): 2 bits say what to do in response
            retry (int): 3 bits say how many times to retry
            delay (int): 3 bits say how much delay to use

        """
        cmd = self.commands.pout_op_fault_response

        return self.fault_response(cmd, response, retry, delay, doRead,
                                   **kwargs)

    def get_pout_op_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.pout_op_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_pout_op_warn_limit(self, pout: int, **kwargs) -> None:
        self.set_pmbus_two(pout, self.commands.pout_op_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def pout_op_warn_limit(self):
        """
        pout_op_warn_limit()

        reads back the pout_op_warn_limit currently set in the slave device
        if pout is provided will set the pout_op_warn_limit

        Args:
            pout (int): if provided will set the pout_op_warn_limit

        Returns:
            int: pout_op_warn_limit set in slave, unsigned, 2 byte
        """
        self._pout_op_warn_limit = self.get_pout_op_warn_limit()
        return self._pout_op_warn_limit

    @pout_op_warn_limit.setter
    def pout_op_warn_limit(self, pout: int) -> None:
        self.set_pout_op_warn_limit(pout)
        return None

    def get_pin_op_warn_limit(self, **kwargs) -> int:
        return self.get_pmbus_two(self.commands.pin_op_warn_limit,
                                  byteorder='little', signed=False, **kwargs)

    def set_pin_op_warn_limit(self, pin: int, **kwargs) -> None:
        self.set_pmbus_two(pin, self.commands.pin_op_warn_limit,
                           byteorder='little', signed=False, **kwargs)
        return None

    @property
    def pin_op_warn_limit(self):
        """
        pin_op_warn_limit()

        reads back the pin_op_warn_limit currently set in the slave device
        if pin is provided will set the pin_op_warn_limit

        Args:
            pin (int): if provided will set the pin_op_warn_limit

        Returns:
            int: pin_op_warn_limit set in slave, unsigned, 2 byte
        """
        self._pin_op_warn_limit = self.get_pin_op_warn_limit()
        return self._pin_op_warn_limit

    @pin_op_warn_limit.setter
    def pin_op_warn_limit(self, pin: int) -> None:
        self.set_pin_op_warn_limit(pin)
        return None

    def express_status(self, byte=False, word=False,
                       vout=False, iout=False, input=False,
                       temp=False, cml=False, other=False,
                       mfr=False, fans1=False, fans2=False, **kwargs) -> dict:
        # not sure this belongs here, idea was maybe to return the string
        # of the flags set as a dict or something. When generating a report,
        # knowing which faults are active is necessary

        # b7_busy
        # b6_off
        # b5_vout_ov
        # b4_iout_oc
        # b3_vin_uv
        # b2_temp
        # b1_cml
        # b0_none

        # b7_vout
        # b6_iout_pout
        # b5_input
        # b4_mfr
        # b3_pwr_gd
        # b2_fans
        # b1_other
        # b0_unknown
        # b7_busy
        # b6_off
        # b5_vout_ov
        # b4_iout_oc
        # b3_vin_uv
        # b2_temp
        # b1_cml
        # b0_none

        # b7_vout_ovf
        # b6_vout_ovw
        # b5_vout_uvw
        # b4_vout_uvf
        # b3_vout_max_min_w
        # b2_ton_max_f
        # b1_toff_max_w
        # b0_vout_trk

        # b7_iout_ocf
        # b6_iout_ocf_lv
        # b5_iout_ocw
        # b4_iout_ucf
        # b3_csf
        # b2_in_plmode
        # b1_pout_opf
        # b0_pout_opw

        # b7_vin_ovf
        # b6_vin_ovw
        # b5_vin_uvw
        # b4_vin_uvf
        # b3_unit_off_low_vin
        # b2_iin_ocf
        # b1_iin_ocw
        # b0_pin_opw

        # b7_otf
        # b6_otw
        # b5_utw
        # b4_utf
        # b3_res
        # b2_res
        # b1_res
        # b0_res

        # b7_invalid_unsupported_command
        # b6_invalid_unsupported_data
        # b5_pec_failed
        # b4_memory_fault
        # b3_proc_fault
        # b2_res
        # b1_other_comm_fault
        # b0_other_mem_logic_fault

        # b7_res
        # b6_res
        # b5_input_a_fuse_f
        # b4_input_b_fuse_f
        # b3_input_a_oring_f
        # b2_input_b_oring_f
        # b1_output_oring_f
        # b0_first_to_smbalert

        # b7
        # b6
        # b5
        # b4
        # b3
        # b2
        # b1
        # b0

        # b7_fan1_f
        # b6_fan2_f
        # b5_fan1_w
        # b4_fan2_w
        # b3_fan1_so
        # b2_fan2_so
        # b1_airflow_f
        # b0_airflow_w

        # b7_fan3_f
        # b6_fan4_f
        # b5_fan3_w
        # b4_fan4_w
        # b3_fan3_so
        # b2_fan4_so
        # b1_res
        # b0_res
        return

    def status_byte(self, **kwargs) -> int:
        """
        status_byte()

        reads back the status_byte currently set in the slave device

        Args:
            None

        Returns:
            int: status_byte set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_byte], 1, **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_byte_bits(self, response, verbose: bool = False) -> tuple:
        b7_busy = bool(response & 0x80)
        b6_off = bool(response & 0x40)
        b5_vout_ov = bool(response & 0x20)
        b4_iout_oc = bool(response & 0x10)
        b3_vin_uv = bool(response & 0x08)
        b2_temp = bool(response & 0x04)
        b1_cml = bool(response & 0x02)
        b0_none = bool(response & 0x01)
        if verbose:
            print('b7_busy =', b7_busy)
            print('b6_off =', b6_off)
            print('b5_vout_ov =', b5_vout_ov)
            print('b4_iout_oc =', b4_iout_oc)
            print('b3_vin_uv =', b3_vin_uv)
            print('b2_temp =', b2_temp)
            print('b1_cml =', b1_cml)
            print('b0_none =', b0_none)
        return(b7_busy, b6_off, b5_vout_ov, b4_iout_oc, b3_vin_uv,
               b2_temp, b1_cml, b0_none)

    def clear_status_byte_bits(self, busy=False, **kwargs) -> None:
        """clear_status_byte(busy)
        There are two bits in STATUS_BYTE and STATUS_WORD that can be cleared
        directly. The BUSY bit in STATUS_BYTE is cleared by sending the
        STATUS_BYTE command with the data byte 80h using the WRITE BYTE
        protocol. The UNKNOWN
        bit in STATUS_WORD is cleared by sending the STATUS_WORD command with
        the data bytes 00h (low order byte) followed by 01h (high order byte)
        using the WRITE WORD protocol.
        As noted above, the OFF and PG_STATUS# bits cannot be cleared as they
        always reflect the current state of the device.
        Args:
            busy (bool, optional): clear the busy bit in status.
            Defaults to False.

        Returns:
            None:
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        if busy:
            self.write_slave([self.commands.status_byte, 0x80], **kwargs)
        return None

    def clear_status_byte(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_word, status], **kwargs)
        return None

    def status_word(self, **kwargs) -> int:
        """
        status_word()

        reads back the status_word currently set in the slave device

        Args:
            None

        Returns:
            int: status_word set in slave, unsigned, 2 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_word], 2, **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def status_word_bits(self, response, verbose: bool = False) -> tuple:
        b7_vout = bool(response & 0x8000)
        b6_iout_pout = bool(response & 0x4000)
        b5_input = bool(response & 0x2000)
        b4_mfr = bool(response & 0x1000)
        b3_pwr_gd = bool(response & 0x0800)
        b2_fans = bool(response & 0x0400)
        b1_other = bool(response & 0x0200)
        b0_unknown = bool(response & 0x0100)
        b7_busy = bool(response & 0x80)
        b6_off = bool(response & 0x40)
        b5_vout_ov = bool(response & 0x20)
        b4_iout_oc = bool(response & 0x10)
        b3_vin_uv = bool(response & 0x08)
        b2_temp = bool(response & 0x04)
        b1_cml = bool(response & 0x02)
        b0_none = bool(response & 0x01)
        if verbose:
            # upper byte
            print('b7_vout =', b7_vout)
            print('b6_iout_pout =', b6_iout_pout)
            print('b5_input =', b5_input)
            print('b4_mfr =', b4_mfr)
            print('b3_pwr_gd =', b3_pwr_gd)
            print('b2_fans =', b2_fans)
            print('b1_other =', b1_other)
            print('b0_unknown =', b0_unknown)

            # lower byte
            print('b7_busy =', b7_busy)
            print('b6_off =', b6_off)
            print('b5_vout_ov =', b5_vout_ov)
            print('b4_iout_oc =', b4_iout_oc)
            print('b3_vin_uv =', b3_vin_uv)
            print('b2_temp =', b2_temp)
            print('b1_cml =', b1_cml)
            print('b0_none =', b0_none)
        return(b7_vout, b6_iout_pout, b5_input, b4_mfr, b3_pwr_gd, b2_fans,
               b1_other, b0_unknown, b7_busy, b6_off, b5_vout_ov,
               b4_iout_oc, b3_vin_uv, b2_temp, b1_cml, b0_none)

    def clear_status_word_bits(self, busy=False, unknown=False,
                               **kwargs) -> None:
        """clear_status_word(busy, unknown)
        There are two bits in STATUS_BYTE and STATUS_WORD that can be cleared
        directly. The BUSY bit in STATUS_BYTE is cleared by sending the
        STATUS_BYTE command with the data byte 80h using the WRITE BYTE
        protocol. The UNKNOWN
        bit in STATUS_WORD is cleared by sending the STATUS_WORD command with
        the data bytes 00h (low order byte) followed by 01h (high order byte)
        using the WRITE WORD protocol.
        As noted above, the OFF and PG_STATUS# bits cannot be cleared as they
        always reflect the current state of the device.
        Args:
            busy (bool, optional): clear the busy bit. Defaults to False.
            unknown (bool, optional): clear the unknown bit. Defaults to False.

        Returns:
            None:
        """
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        if busy:
            byte = 0x80
        if unknown:
            word = 0x01
        if busy or unknown:
            self.write_slave([self.commands.status_byte, byte, word], **kwargs)
        return None

    def clear_status_word(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        payload = status.to_bytes(2, byteorder='little', signed=False)
        self.write_slave([self.commands.status_word, *payload], **kwargs)
        return None

    def status_vout(self, **kwargs) -> int:
        """
        status_vout()

        reads back the status_vout currently set in the slave device

        Args:
            None

        Returns:
            int: status_vout set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_vout], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_vout_bits(self, response, verbose: bool = False) -> tuple:
        b7_vout_ovf = bool(response & 0x80)
        b6_vout_ovw = bool(response & 0x40)
        b5_vout_uvw = bool(response & 0x20)
        b4_vout_uvf = bool(response & 0x10)
        b3_vout_max_min_w = bool(response & 0x08)
        b2_ton_max_f = bool(response & 0x04)
        b1_toff_max_w = bool(response & 0x02)
        b0_vout_trk = bool(response & 0x01)
        if verbose:
            print('b7_vout_ovf =', b7_vout_ovf)
            print('b6_vout_ovw =', b6_vout_ovw)
            print('b5_vout_uvw =', b5_vout_uvw)
            print('b4_vout_uvf =', b4_vout_uvf)
            print('b3_vout_max_min_w =', b3_vout_max_min_w)
            print('b2_ton_max_f =', b2_ton_max_f)
            print('b1_toff_max_w =', b1_toff_max_w)
            print('b0_vout_trk =', b0_vout_trk)
        return(b7_vout_ovf, b6_vout_ovw, b5_vout_uvw, b4_vout_uvf,
               b3_vout_max_min_w, b2_ton_max_f, b1_toff_max_w, b0_vout_trk)

    def clear_status_vout(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_vout, status], **kwargs)
        return None

    def status_iout(self, **kwargs) -> int:
        """
        status_iout()

        reads back the status_iout currently set in the slave device

        Args:
            None

        Returns:
            int: status_iout set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_iout], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_iout_bits(self, response, verbose: bool = False) -> tuple:
        b7_iout_ocf = bool(response & 0x80)
        b6_iout_ocf_lv = bool(response & 0x40)
        b5_iout_ocw = bool(response & 0x20)
        b4_iout_ucf = bool(response & 0x10)
        b3_csf = bool(response & 0x08)
        b2_in_plmode = bool(response & 0x04)
        b1_pout_opf = bool(response & 0x02)
        b0_pout_opw = bool(response & 0x01)
        if verbose:

            print('b7_iout_ocf =', b7_iout_ocf)
            print('b6_iout_ocf_lv =', b6_iout_ocf_lv)
            print('b5_iout_ocw =', b5_iout_ocw)
            print('b4_iout_ucf =', b4_iout_ucf)
            print('b3_csf =', b3_csf)
            print('b2_in_plmode =', b2_in_plmode)
            print('b1_pout_opf =', b1_pout_opf)
            print('b0_pout_opw =', b0_pout_opw)
        return(b7_iout_ocf, b6_iout_ocf_lv, b5_iout_ocw, b4_iout_ucf,
               b3_csf, b2_in_plmode, b1_pout_opf, b0_pout_opw)

    def clear_status_iout(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_iout, status], **kwargs)
        return None

    def status_input(self, **kwargs) -> int:
        """
        status_input()

        reads back the status_input currently set in the slave device

        Args:
            None

        Returns:
            int: status_input set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_input], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_input_bits(self, response, verbose: bool = False) -> tuple:
        b7_vin_ovf = bool(response & 0x80)
        b6_vin_ovw = bool(response & 0x40)
        b5_vin_uvw = bool(response & 0x20)
        b4_vin_uvf = bool(response & 0x10)
        b3_unit_off_low_vin = bool(response & 0x08)
        b2_iin_ocf = bool(response & 0x04)
        b1_iin_ocw = bool(response & 0x02)
        b0_pin_opw = bool(response & 0x01)
        if verbose:
            print('b7_vin_ovf =', b7_vin_ovf)
            print('b6_vin_ovw =', b6_vin_ovw)
            print('b5_vin_uvw =', b5_vin_uvw)
            print('b4_vin_uvf =', b4_vin_uvf)
            print('b3_unit_off_low_vin =', b3_unit_off_low_vin)
            print('b2_iin_ocf =', b2_iin_ocf)
            print('b1_iin_ocw =', b1_iin_ocw)
            print('b0_pin_opw =', b0_pin_opw)

        return(b7_vin_ovf, b6_vin_ovw, b5_vin_uvw, b4_vin_uvf,
               b3_unit_off_low_vin, b2_iin_ocf, b1_iin_ocw, b0_pin_opw)

    def clear_status_input(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_input, status], **kwargs)
        return None

    def status_temperature(self, **kwargs) -> int:
        """
        status_temperature()

        reads back the status_temperature currently set in the slave device

        Args:
            None

        Returns:
            int: status_temperature set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_temperature], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_temperature_bits(self, response,
                                verbose: bool = False) -> tuple:
        b7_otf = bool(response & 0x80)
        b6_otw = bool(response & 0x40)
        b5_utw = bool(response & 0x20)
        b4_utf = bool(response & 0x10)
        b3_res = bool(response & 0x08)
        b2_res = bool(response & 0x04)
        b1_res = bool(response & 0x02)
        b0_res = bool(response & 0x01)
        if verbose:

            print('b7_otf =', b7_otf)
            print('b6_otw =', b6_otw)
            print('b5_utw =', b5_utw)
            print('b4_utf =', b4_utf)
            print('b3_res =', b3_res)
            print('b2_res =', b2_res)
            print('b1_res =', b1_res)
            print('b0_res =', b0_res)
        return(b7_otf, b6_otw, b5_utw, b4_utf, b3_res, b2_res, b1_res, b0_res)

    def clear_status_temperature(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_temperature, status], **kwargs)
        return None

    def status_cml(self, **kwargs) -> int:
        """
        status_cml()

        reads back the status_cml currently set in the slave device

        Args:
            None

        Returns:
            int: status_cml set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_cml], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_cml_bits(self, response, verbose: bool = False) -> tuple:
        b7_invalid_unsupported_command = bool(response & 0x80)
        b6_invalid_unsupported_data = bool(response & 0x40)
        b5_pec_failed = bool(response & 0x20)
        b4_memory_fault = bool(response & 0x10)
        b3_proc_fault = bool(response & 0x08)
        b2_res = bool(response & 0x04)
        b1_other_comm_fault = bool(response & 0x02)
        b0_other_mem_logic_fault = bool(response & 0x01)
        if verbose:
            print('b7_invalid_unsupported_command=',
                  b7_invalid_unsupported_command)
            print('b6_invalid_unsupported_data =', b6_invalid_unsupported_data)
            print('b5_pec_failed =', b5_pec_failed)
            print('b4_memory_fault =', b4_memory_fault)
            print('b3_proc_fault =', b3_proc_fault)
            print('b2_res =', b2_res)
            print('b1_other_comm_fault =', b1_other_comm_fault)
            print('b0_other_mem_logic_fault =', b0_other_mem_logic_fault)
        return(b7_invalid_unsupported_command, b6_invalid_unsupported_data,
               b5_pec_failed, b4_memory_fault, b3_proc_fault, b2_res,
               b1_other_comm_fault, b0_other_mem_logic_fault)

    def clear_status_cml(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_cml, status], **kwargs)
        return None

    def status_other(self, **kwargs) -> int:
        """
        status_other()

        reads back the status_other currently set in the slave device

        Args:
            None

        Returns:
            int: status_other set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_other], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_other_bits(self, response, verbose: bool = False) -> tuple:
        b7_res = bool(response & 0x80)
        b6_res = bool(response & 0x40)
        b5_input_a_fuse_f = bool(response & 0x20)
        b4_input_b_fuse_f = bool(response & 0x10)
        b3_input_a_oring_f = bool(response & 0x08)
        b2_input_b_oring_f = bool(response & 0x04)
        b1_output_oring_f = bool(response & 0x02)
        b0_first_to_smbalert = bool(response & 0x01)
        if verbose:
            print('b7_res =', b7_res)
            print('b6_res =', b6_res)
            print('b5_input_a_fuse_f =', b5_input_a_fuse_f)
            print('b4_input_b_fuse_f =', b4_input_b_fuse_f)
            print('b3_input_a_oring_f =', b3_input_a_oring_f)
            print('b2_input_b_oring_f =', b2_input_b_oring_f)
            print('b1_output_oring_f =', b1_output_oring_f)
            print('b0_first_to_smbalert =', b0_first_to_smbalert)
        return(b7_res, b6_res, b5_input_a_fuse_f, b4_input_b_fuse_f,
               b3_input_a_oring_f, b2_input_b_oring_f, b1_output_oring_f,
               b0_first_to_smbalert)

    def clear_status_other(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_other, status], **kwargs)
        return None

    def status_mfr_specific(self, **kwargs) -> int:
        """
        status_mfr_specific()

        reads back the status_mfr_specific currently set in the slave device

        Args:
            None

        Returns:
            int: status_mfr_specific set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_mfr_specific], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_mfr_bits(self, response, verbose: bool = False) -> tuple:
        b7 = bool(response & 0x80)
        b6 = bool(response & 0x40)
        b5 = bool(response & 0x20)
        b4 = bool(response & 0x10)
        b3 = bool(response & 0x08)
        b2 = bool(response & 0x04)
        b1 = bool(response & 0x02)
        b0 = bool(response & 0x01)
        if verbose:
            print('b7 =', b7)
            print('b6 =', b6)
            print('b5 =', b5)
            print('b4 =', b4)
            print('b3 =', b3)
            print('b2 =', b2)
            print('b1 =', b1)
            print('b0 =', b0)
        return(b7, b6, b5, b4, b3, b2, b1, b0)

    def clear_status_mfr_specific(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_mfr_specific, status], **kwargs)
        return None

    def status_fans_1_2(self, **kwargs) -> int:
        """
        status_fans_1_2()

        reads back the status_fans_1_2 currently set in the slave device

        Args:
            None

        Returns:
            int: status_fans_1_2 set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_fans_1_2], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_fans_1_2_bits(self, response, verbose: bool = False) -> tuple:
        b7_fan1_f = bool(response & 0x80)
        b6_fan2_f = bool(response & 0x40)
        b5_fan1_w = bool(response & 0x20)
        b4_fan2_w = bool(response & 0x10)
        b3_fan1_so = bool(response & 0x08)
        b2_fan2_so = bool(response & 0x04)
        b1_airflow_f = bool(response & 0x02)
        b0_airflow_w = bool(response & 0x01)
        if verbose:
            print('b7_fan1_f =', b7_fan1_f)
            print('b6_fan2_f =', b6_fan2_f)
            print('b5_fan1_w =', b5_fan1_w)
            print('b4_fan2_w =', b4_fan2_w)
            print('b3_fan1_so =', b3_fan1_so)
            print('b2_fan2_so =', b2_fan2_so)
            print('b1_airflow_f =', b1_airflow_f)
            print('b0_airflow_w =', b0_airflow_w)

        return(b7_fan1_f, b6_fan2_f, b5_fan1_w, b4_fan2_w, b3_fan1_so,
               b2_fan2_so, b1_airflow_f, b0_airflow_w)

    def clear_status_fans_1_2(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_fans_1_2, status], **kwargs)
        return None

    def status_fans_3_4(self, **kwargs) -> int:
        """
        status_fans_3_4()

        reads back the status_fans_3_4 currently set in the slave device

        Args:
            None

        Returns:
            int: status_fans_3_4 set in slave, unsigned, 1 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)

        response = self.query_slave([self.commands.status_fans_3_4], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def status_fans_3_4_bits(self, response, verbose: bool = False) -> tuple:
        b7_fan3_f = bool(response & 0x80)
        b6_fan4_f = bool(response & 0x40)
        b5_fan3_w = bool(response & 0x20)
        b4_fan4_w = bool(response & 0x10)
        b3_fan3_so = bool(response & 0x08)
        b2_fan4_so = bool(response & 0x04)
        b1_res = bool(response & 0x02)
        b0_res = bool(response & 0x01)
        if verbose:
            print('b7_fan3_f =', b7_fan3_f)
            print('b6_fan4_f =', b6_fan4_f)
            print('b5_fan3_w =', b5_fan3_w)
            print('b4_fan4_w =', b4_fan4_w)
            print('b3_fan3_so =', b3_fan3_so)
            print('b2_fan4_so =', b2_fan4_so)
            print('b1_res =', b1_res)
            print('b0_res =', b0_res)
        return(b7_fan3_f, b6_fan4_f, b5_fan3_w, b4_fan4_w, b3_fan3_so,
               b2_fan4_so, b1_res, b0_res)

    def clear_status_fans_3_4(self, status: int, **kwargs) -> None:
        kwargs['relax'] = kwargs.get('relax', True)
        kwargs['start'] = kwargs.get('start', True)
        self.write_slave([self.commands.status_fans_3_4, status], **kwargs)
        return None

    def read_kwh_in(self, **kwargs):
        """
        read_kwh_in()

        reads back the read_kwh_in

        Args:
            none

        Returns:
            int: read_kwh_in set in slave, unsigned, 4 byte
            note, the data could be ieee-754 floating point
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_kwh_in], 4,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def read_kwh_out(self, **kwargs):
        """
        read_kwh_out()

        reads back the read_kwh_out

        Args:
            none

        Returns:
            int: read_kwh_out set in slave, unsigned, 4 byte
            note, the data could be ieee-754 floating point
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_kwh_out], 4,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        return response

    def read_kwh_config(self, reset_acc_in: bool = False,
                        reset_acc_out: bool = False, **kwargs):
        """
        read_kwh_config()

        reads back the read_kwh_config currently set in the slave device
        If the device supports resetting an energy accumulator (bit [2] = 1),
        then the energy
        accumulator is reset by writing a 1 to the bit [0] of the appropriate
        byte.
        • If the device supports the READ_KWH_IN command and resetting the
        input energy
        accumulator, the accumulator is reset by writing a 1 to bit [0] of
        the high byte (data
        value 0100h).
        • If the device supports the READ_KWH_OUT command and resetting the
        output
        energy accumulator, the accumulator is reset by writing a 1 to bit
        [0] of the low byte
        (data value 0001h).
        • If the device supports the READ_KWH_IN and READ_KWH_OUT commands
        and
        resetting the both energy accumulators, the both accumulators are
        simultaneously
        reset by writing a 1 to bit [0] of each byte (data value 0101h).

        Args:
            reset_acc_in (bool): 1 bit reset the input energy accumulator
            reset_acc_out (bool): 1 bit reset the output energy accumulator

        Returns:
            response (int): the read_kwh_config, 2 bytes, unsigned

        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        dowrite = reset_acc_in | reset_acc_out

        if dowrite:
            kwargs['relax'] = True  # special case
            assembly = (reset_acc_in << 8) | (reset_acc_out)
            abytes = assembly.to_bytes(2, byteorder='big', signed=False)
            self.write_slave([self.commands.read_kwh_config, abytes],
                             **kwargs)
            return None
        else:
            response = self.query_slave([self.commands.read_kwh_config],
                                        2, **kwargs)
            response = int.from_bytes(response, byteorder='little',
                                      signed=False)

        return (response)

    def read_ein(self, **kwargs):
        """
        read_ein()

        reads back the read_ein

        Args:
            none

        Returns:
            energy_count (int): unsigned 2 byte
            rollover (int): unsigned 1 byte
            sample_count (int): unsigned 3 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_ein], 7,
                                    **kwargs)
        energy_count = int.from_bytes(response[1:3], byteorder='little',
                                      signed=False)
        rollover = int.from_bytes(response[3:4], byteorder='little',
                                  signed=False)
        sample_count = int.from_bytes(response[4:7], byteorder='little',
                                      signed=False)

        return (energy_count, rollover, sample_count)

    def read_eout(self, **kwargs):
        """
        read_eout()

        reads back the read_eout

        Args:
            none

        Returns:
            energy_count (int): unsigned 2 byte
            rollover (int): unsigned 1 byte
            sample_count (int): unsigned 3 byte
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_eout], 7,
                                    **kwargs)
        energy_count = int.from_bytes(response[1:3], byteorder='little',
                                      signed=False)
        rollover = int.from_bytes(response[3:4], byteorder='little',
                                  signed=False)
        sample_count = int.from_bytes(response[4:7], byteorder='little',
                                      signed=False)

        return (energy_count, rollover, sample_count)

    def read_vin(self, **kwargs):
        """
        read_vin()

        reads back the read_vin

        Args:
            none

        Returns:
            int: read_vin set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_vin = instance.decode_lin11(read_vin)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_vin], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_iin(self, **kwargs):
        """
        read_iin()

        reads back the read_iin

        Args:
            none

        Returns:
            int: read_iin set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_iin = instance.decode_lin11(read_iin)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_iin], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_vcap(self, **kwargs):
        """
        read_vcap()

        reads back the read_vcap

        Args:
            none

        Returns:
            int: read_vcap set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_vcap = instance.decode_lin11(read_vcap)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_vcap], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_vout(self, **kwargs):
        """
        read_vout()

        reads back the read_vout

        Args:
            none

        Returns:
            int: read_vout set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_vout = instance.decode_lin11(read_vout)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_vout], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_iout(self, **kwargs):
        """
        read_iout()

        reads back the read_iout

        Args:
            none

        Returns:
            int: read_iout set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_iout = instance.decode_lin11(read_iout)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_iout], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_temperature_1(self, **kwargs):
        """
        read_temperature_1()

        reads back the read_temperature_1

        Args:
            none

        Returns:
            int: read_temperature_1 set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_temperature_1 = instance.decode_lin11(read_temperature_1)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_temperature_1], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_temperature_2(self, **kwargs):
        """
        read_temperature_2()

        reads back the read_temperature_2

        Args:
            none

        Returns:
            int: read_temperature_2 set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_temperature_2 = instance.decode_lin11(read_temperature_2)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_temperature_2], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_temperature_3(self, **kwargs):
        """
        read_temperature_3()

        reads back the read_temperature_3

        Args:
            none

        Returns:
            int: read_temperature_3 set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_temperature_3 = instance.decode_lin11(read_temperature_3)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_temperature_3], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_fan_speed_1(self, **kwargs):
        """
        read_fan_speed_1()

        reads back the read_fan_speed_1

        Args:
            none

        Returns:
            int: read_fan_speed_1 set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_fan_speed_1 = instance.decode_lin11(read_fan_speed_1)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_fan_speed_1], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_fan_speed_2(self, **kwargs):
        """
        read_fan_speed_2()

        reads back the read_fan_speed_2

        Args:
            none

        Returns:
            int: read_fan_speed_2 set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_fan_speed_2 = instance.decode_lin11(read_fan_speed_2)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_fan_speed_2], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_fan_speed_3(self, **kwargs):
        """
        read_fan_speed_3()

        reads back the read_fan_speed_3

        Args:
            none

        Returns:
            int: read_fan_speed_3 set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_fan_speed_3 = instance.decode_lin11(read_fan_speed_3)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_fan_speed_3], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_fan_speed_4(self, **kwargs):
        """
        read_fan_speed_4()

        reads back the read_fan_speed_4

        Args:
            none

        Returns:
            int: read_fan_speed_4 set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_fan_speed_4 = instance.decode_lin11(read_fan_speed_4)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_fan_speed_4], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_duty_cycle(self, **kwargs):
        """
        read_duty_cycle()

        reads back the read_duty_cycle

        Args:
            none

        Returns:
            int: read_duty_cycle set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_duty_cycle = instance.decode_lin11(read_duty_cycle)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_duty_cycle], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_frequency(self, **kwargs):
        """
        read_frequency()

        reads back the read_frequency

        Args:
            none

        Returns:
            int: read_frequency set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_frequency = instance.decode_lin11(read_frequency)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_frequency], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_pout(self, **kwargs):
        """
        read_pout()

        reads back the read_pout

        Args:
            none

        Returns:
            int: read_pout set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_pout = instance.decode_lin11(read_pout)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_pout], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def read_pin(self, **kwargs):
        """
        read_pin()

        reads back the read_pin

        Args:
            none

        Returns:
            int: read_pin set in slave, unsigned, 2 bytes
            Note, use another function to decode the returned value
            i.e. read_pin = instance.decode_lin11(read_pin)
        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.read_pin], 2,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)

        return response

    def pmbus_revision(self, verbose: bool = False, **kwargs):
        """
        pmbus_revision()

        reads back the pmbus_revision

        Args:
            verbose (bool): prints the pmbus version

        Returns:
            int: pmbus_revision set in slave, unsigned, 1 bytes

        """
        kwargs['relax'] = kwargs.get('relax', False)
        kwargs['start'] = kwargs.get('start', True)
        response = self.query_slave([self.commands.pmbus_revision], 1,
                                    **kwargs)
        response = int.from_bytes(response, byteorder='little', signed=False)
        if verbose:
            version = 1 + response/10
            print('PMBus Revision=', version)
        return response


if __name__ == '__main__':
    # these are only executed if THIS module is the main program, if you
    # import it this is skipped
    pmbus_addr = 0x4C
    ftdi_dongle = 'ftdi://ftdi:232h:FT0NCMMI/1'
    dopmbus = PMBus(pmbus_addr, ftdi_dongle, frequency=25000)
    # i2c.configure('ftdi://ftdi:232h:FT0NCMMI/1') # (C232HM-EDHSL-0) 5V
    # i2c.configure('ftdi://ftdi:232h:FT0J75U1/1') # (C232HM-DDHSL-0) 3.3V
