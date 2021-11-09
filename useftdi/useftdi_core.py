from pyftdi.i2c import I2cController, I2cNackError, I2cIOError
from pyftdi.ftdi import Ftdi, FtdiError
import struct
import time
from io import StringIO
from contextlib import redirect_stdout
import warnings
from collections import namedtuple
from math import log, ceil, floor


class Use_Ftdi():

    def __init__(self, pmbus_addr=None, ftdi=None, **kwargs) -> None:
        """
        Use_Ftdi(pmbus_addr, ftdi=None, **kwargs)

        Base class for interfacing with various I2C integrated circuits.
        Use_Ftdi handles creating and utilizing connections with IC's using
        an FTDI dongle, managing connections to both the FTDI dongle and to the
        target I2C device through the dongle.

        Use_Ftdi also contains various methods for performing data type
        conversions between commonly used data types with PMBus systems.

        Args:
            pmbus_addr (int): I2C address of the IC to connect to with the FTDI
                dongle.
            ftdi ([str, I2cController, Use_Ftdi, None], optional): Argument
                which determines how the instance will connect with the FTDI
                dongle. Can be an FTDI url (str) of a connected dongle, an
                existing I2cController instance, or another Use_Ftdi instance
                in which case it will use the it's existing I2cController
                instance. If set to None the __init__ method will attempt to
                discover connected dongles, connecting to the first dongle
                found. Defaults to None.
        Kwargs:
            Any kwargs passed are used to configure the Use_Ftdi's
            I2cController instance. These parameters are passed after
            establishing the connection to the FTDI dongle, or after linking
            with an existing connection.
        Raises:
            OSError: Raised when the __init__ method attempts to find connected
                dongles but fails to find any.

        Returns:
            None
        """
        self.pmbus_addr = pmbus_addr

        if isinstance(ftdi, (I2cController, Use_Ftdi)):  # use existing i2c

            try:
                self.i2c_master = ftdi.i2c_master
            except AttributeError:  # means not initialized, or came direct
                if isinstance(ftdi, I2cController):  # direct pass in way
                    self.i2c_master = ftdi

            if isinstance(ftdi.ftdi_url, str):  # if an instance it has a URL!
                self.ftdi_url = ftdi.ftdi_url
            else:
                # this next url code assumes its the first dongle found. this
                # should be a valid assumption, because an instance was passed
                # so the only url is probably that of the passed instance
                print("no ftdi url passed, building one assuming device 0!")
                idn = self.i2c_master.ftdi.list_devices()[0][0]

                self.ftdi_url = 'ftdi://{}:{}:{}/{}'.format(idn.vid, idn.pid,
                                                            idn.sn,
                                                            idn.address)

        else:  # make a new connection
            self.i2c_master = I2cController()

            if ftdi is None:  # url was not passed
                # gets first found
                try:
                    self.ftdi_url = get_available_ftdi_urls()[0][0]
                except IndexError:
                    raise OSError('No FTDI device connections were found, '
                                  'unable to connect')
            else:
                self.ftdi_url = ftdi  # this only runs when a URL is passed in

        if kwargs:
            self.i2c_master.configure(self.ftdi_url, **kwargs)
            self.options = kwargs  # provided so they can be retrieved
            # note that if no kwargs are passed in, doesn't erase what we had!
        else:
            if isinstance(ftdi, Use_Ftdi):
                self.options = ftdi.options
            else:  # new instance made, and no kwargs.. configure as default
                self.i2c_master.configure(self.ftdi_url)
                self.options = {}  # if it gets here the options are defaults

        try:
            self.devices = ftdi.devices
        except AttributeError:
            self.devices = {}  # keep a list of devices interacted with

        if pmbus_addr is not None:  # no need to if this is the instance
            # of the master....
            self.i2c_slave = self.i2c_master.get_port(pmbus_addr)
            self.devices[pmbus_addr] = self.i2c_slave
            # could consider just going to get all addresses now.. why not?
        if kwargs.get('use_wide_port', False):
            self.gpio_width = self.gpio().width
        else:
            self.gpio_width = 8
        self.gpio_settle = kwargs.get('gpio_settle', 0.050)
        self.gpio_pins = self.gpio().all_pins & ((1 << self.gpio_width) - 1)
        self.gpio_master_mask = self.i2c_master._gpio_mask

        return None

    def __del__(self, **kwargs) -> None:
        if hasattr(self, 'i2c_master'):
            self.i2c_master.terminate(**kwargs)
        return None

    def __repr__(self) -> str:
        if self.pmbus_addr is not None:
            desc = '{}({}, ftdi={}, **{})'.format(self.__class__.__name__,
                                                  hex(self.pmbus_addr),
                                                  self.ftdi_url,
                                                  self.options)
        else:
            desc = '{}(ftdi={}, **{})'.format(self.__class__.__name__,
                                              self.ftdi_url,
                                              self.options)
        return desc

    # communication related methods
    @property
    def i2c_frequency(self):
        return self.i2c_master.frequency

    @property
    def address(self):
        try:
            return self.i2c_slave.address
        except AttributeError:
            return None

    def set_address(self, address: int) -> None:
        self.i2c_slave = self.i2c_master.get_port(address)
        self.devices[address] = self.i2c_slave
        return None

    @property
    def retry_count(self):
        return self.i2c_master.RETRY_COUNT

    @retry_count.setter
    def retry_count(self, count):

        if not isinstance(count, int):
            raise ValueError('Retry count must be of type int')

        self.i2c_master.set_retry_count(count)
        return None

    def query_slave(self, payload, n_bytes: int, **kwargs) -> bytearray:
        """
        query_slave(payload, n_bytes)

        Writes a data to the i2c slave device at "self.pmbus_addr" before
        reading back "n_bytes" of data.

        Args:
            payload (bytes, bytearray, Iterable[int]): Command to send to the
                    i2c host before reading the response.
            n_bytes (int): number of bytes to read back from the slave device.
        Kwargs:
            relax (bool): True = Finish transaction with i2c stop and release
                          bus, Default is False.
            start (bool): True = send start or repeated start with transaction
                          Default is True.
            retry_on_error (bool): Whether or not to retry the query after an
                                   exception is caught and handled. Retries the
                                   query 1 time. Default is True.
            verbose (bool): Whether or not to print debug messages if
                            exceptions caught are thrown. Default is False.
        Returns:
            byte (bytearray): response from the slave device.
        """

        start = kwargs.get('start', True)
        relax = kwargs.get('relax', False)

        # check payload is valid
        if not isinstance(payload, (list, tuple, bytes, bytearray)):
            warnings.warn(f"Warning, payload={payload} is wrong type, "
                          "unexpected results may occur!")
            if isinstance(payload, int):
                payload = payload.to_bytes((payload.bit_length() + 7) // 8,
                                           byteorder='big', signed=False)
            else:
                # prevent invalid dtype from being sent (ex. float, str)
                raise ValueError('Argument "payload" must be an iterable '
                                 '(list, tuple, bytes, bytearray) of type int,'
                                 ' or type int')

        try:
            response = self.i2c_slave.exchange(payload, n_bytes,
                                               start=start, relax=relax)

        # the dongle timed out, which can be for a lot of reasons
        except I2cIOError:
            if kwargs.get('verbose', False):
                print('I2cIOError, FTDI controller was not initialized, '
                      'fixing...')
            self.i2c_master.flush()  # flush HW FIFOs

            # Option to try again after failure
            if kwargs.get('retry_on_error', True):
                kwargs['retry_on_error'] = False
                response = self.query_slave(payload, n_bytes, **kwargs)
            else:
                raise I2cIOError

        return response

    def write_slave(self, payload, **kwargs) -> None:
        """
        write_slave(payload)

        Writes a data to the i2c slave device at "self.pmbus_addr".

        Args:
            payload (bytes, bytearray, Iterable[int]): Command to send to the
            i2c device.
        Kwargs:
            relax (bool): True = Finish transaction with i2c stop and release
                          bus, Default is False
            start (bool): True = send start or repeated start with transaction
                          Default is True
            retry_on_error (bool): Whether or not to retry the write after an
                                   exception is caught and handled. Retries the
                                   write 1 time. Default is True.
            verbose (bool): Whether or not to print debug messages if
                            exceptions caught are thrown. Default is False.
        Returns:
            None
        """

        start = kwargs.get('start', True)
        relax = kwargs.get('relax', False)

        # check payload is valid
        if not isinstance(payload, (list, tuple, bytes, bytearray)):
            warnings.warn(f"Warning, payload={payload} is wrong type, "
                          "unexpected results may occur!")
            if isinstance(payload, int):
                payload = payload.to_bytes((payload.bit_length() + 7) // 8,
                                           byteorder='big', signed=False)
            else:
                # prevent invalid dtype from being sent (ex. float, str)
                raise ValueError('Argument "payload" must be an iterable '
                                 '(list, tuple, bytes, bytearray) of type int,'
                                 ' or type int')

        try:
            self.i2c_slave.write(payload, start=start, relax=relax)

        # the dongle timed out, which can be for a lot of reasons
        except I2cIOError:
            if kwargs.get('verbose', False):
                print('I2cIOError, FTDI controller was not initialized, '
                      'fixing...')
            self.i2c_master.flush()  # flush HW FIFOs

            # Option to try again after failure
            if kwargs.get('retry_on_error', True):
                kwargs['retry_on_error'] = False
                self.write_slave(payload, **kwargs)
            else:
                raise I2cIOError

        return None

    def read_slave(self, n_bytes: int, **kwargs) -> bytearray:
        """
        write_slave(payload)

        reads the data from the i2c slave device at "self.pmbus_addr".

        Args:
            payload (none): Command to send to the
            i2c device.
        Kwargs:
            relax (bool): True = Finish transaction with i2c stop and release
                          bus, Default is False.
            start (bool): True = send start or repeated start with transaction
                          Default is True.
            retry_on_error (bool): Whether or not to retry the read after an
                                   exception is caught and handled. Retries the
                                   read 1 time. Default is True.
            verbose (bool): Whether or not to print debug messages if
                            exceptions caught are thrown. Default is False.
        Returns:
            byte (bytearray): response from the slave device.
        """

        start = kwargs.get('start', True)
        relax = kwargs.get('relax', False)

        try:
            response = self.i2c_slave.read(n_bytes, relax=relax, start=start)

        # the dongle timed out, which can be for a lot of reasons
        except I2cIOError:
            if kwargs.get('verbose', False):
                print('I2cIOError, FTDI controller was not initialized, '
                      'fixing...')
            self.i2c_master.flush()  # flush HW FIFOs

            # Option to try again after failure
            if kwargs.get('retry_on_error', True):
                kwargs['retry_on_error'] = False
                response = self.read_slave(n_bytes, **kwargs)
            else:
                raise I2cIOError

        return response

    def find_i2c_devices(self, i2c_addr: int = None, **kwargs) -> list:
        """
        find_i2c_devices(i2c_addr=None, verbose=False, show_nack=False)

        tests for ACK bit response from I2C slaves
        Use i2c_addr to test a specific slave or omit to list them all

        Args:
            i2c_addr (int): address on the bus to check, if None (default) will
                            default to searching the range 0x00 to 0x7F
            verbose (bool): print addresses found or not. Defaults to False.
            show_nack (bool): Whether or not to display addresses that nack'ed.
                              Defaults to False.
            retry_on_error (bool): Whether or not to retry the query after an
                                   exception is caught and handled. Retries the
                                   query 1 time. Default is True.

        Returns:
            list: addresses (int) that responded on the I2C Bus
        """

        initial_retry_count = self.retry_count
        self.retry_count = 1  # don't need retrys finding

        verbose = kwargs.get('verbose', False)
        show_nack = kwargs.get('show_nack', False)

        i2c_devices = []
        addr_list = ([i2c_addr] if i2c_addr is not None else range(0x7F + 1))
        N = len(addr_list)

        for i, addr in enumerate(addr_list):
            try:
                self.i2c_master.read(addr, 0, relax=(i == N - 1))
                i2c_devices.append(addr)
                if verbose:
                    print(f'found address: {hex(addr)}')

            except I2cNackError:  # no response from address
                if show_nack:
                    print(f'nack from: {hex(addr)}')

            except I2cIOError:

                # the dongle timed out, which can be for a lot of reasons
                if verbose:
                    print('FTDI controller was not initialized, fixing...')
                self.i2c_master.configure(self.ftdi_url,
                                          **self.options)
                # this is brute force, because if it hits here, chances
                # are that the options are gone, and clock stretching
                # is off, and frequency is very high

                if kwargs.get('retry_on_error', True):
                    try:  # because it failed, lets try this position again
                        self.i2c_master.read(addr, 0, relax=(i == N - 1))
                        i2c_devices.append(addr)
                        self.devices[addr] = self.i2c_master.get_port(addr)
                        if verbose:
                            print(f'found retry address: {hex(addr)}')
                    except I2cNackError:  # no response from address
                        if show_nack:
                            print(f'nack from: {hex(addr)}')

                    # the dongle timed out, which can be for a lot of reasons
                    except I2cIOError:
                        self.i2c_master.configure(self.ftdi_url,
                                                  **self.options)
                        # this is brute force, because if it hits here, chances
                        # are that the options are gone, and clock stretching
                        # is off, and frequency is very high
                        if verbose:
                            print('FTDI controller timeout again...'
                                  'corrective action taken: master.configure'
                                  ' there were likely no addresses returned!')
                else:
                    raise I2cIOError

        self.retry_count = initial_retry_count  # revert
        return i2c_devices

    def reset_i2c_devices(self) -> None:
        """
        reset_i2c_devices()

        Sends general_call address (0x00) and bus reset data (0x06)
        Note, devices with software assignable addresses will reset
        their addresses to default offset

        Returns:
            None
        """

        self.i2c_master.write(0x00, 0x06)
        return None

    def gpio(self):
        """
        gpio()

        passes control of the gpio's on i2c_master to the user
        Note: the user should pass in kwargs to setup the gpios on the instance
        These parameters such as:
            'initial': 0x78,
            'direction': 0x78
        set the initial state of the pin drivers and their direction i/o

        Use Examples:
            # return state of the pins, only returns input pins by default
            gpio.read()

            # return the state of the pins, includes all pins input and outputs
            gpio.read(with_output=True)

            # set the pin directions per mask
            gpio.set_direction(mask)

            gpio.write(data)  # set the pins to data state

        Returns:
            instance of i2c_master.gpio

            (control of) the gpio instance
            WARNING! GPIO STATE ON EXIT UNKNOWN!
        """

        return self.i2c_master.get_gpio()

    def gpio_val(self, pin: int = 0) -> bool:
        """gpio_val(pin)
        0 = C232HM dongle BROWN WIRE - AKA CS
        1 = C232HM dongle GREY WIRE - AKA GPIOL0
        2 = C232HM dongle PURPLE WIRE - AKA GPIOL1
        3 = C232HM dongle WHITE WIRE - AKA GPIOL3

        Args:
            gpio (instance): gpio instance
            pin (int): gpio pin to control

        Returns:
            bool: pin state high = True, low = False
        """
        if pin < 0:
            print(f"invalid pin #{pin}, use 3-0, used: 0")
            pin = 0
        elif pin > 3:
            print(f"invalid pin #{pin}, use 3-0, used: 3")
            pin = 3
        gpio_position = pin + 3  # bit number 3

        pins_states = self.gpio().read(with_output=True)
        self.options['initial'] = pins_states & self.gpio_master_mask
        return (pins_states >> gpio_position) & 1

    def set_gpio_val(self, pin, state: bool = False, **kwargs) -> bool:
        """gpio(pin, state)
        0 = C232HM dongle BROWN WIRE - AKA CS
        1 = C232HM dongle GREY WIRE - AKA GPIOL0
        2 = C232HM dongle PURPLE WIRE - AKA GPIOL1
        3 = C232HM dongle WHITE WIRE - AKA GPIOL3

        Args:
            state (bool, optional): drive state for pin. Defaults to False.
            pin (int): gpio pin to control

        Returns:
            bool: pin state high = True, low = False
        """
        if pin < 0:
            print(f"invalid pin #{pin}, use 3-0, used: 0")
            pin = 0
        elif pin > 3:
            print(f"invalid pin #{pin}, use 3-0, used: 3")
            pin = 3
        gpio_position = pin + 3  # bit number 3
        pin_mask = 1 << gpio_position
        pins_states = self.gpio().read(with_output=True, **kwargs) & 0x78
        if state:
            # Note: drive == 1 is HIGH
            new_pins_states = pins_states | pin_mask
        else:
            # Note: drive == 0 is LOW
            new_pins_states = pins_states & ~pin_mask
        try:
            self.gpio().write(new_pins_states, **kwargs)
        except I2cIOError:
            temp = ((self.gpio().direction >> gpio_position) & 1)
            print(f"gpio:{pin} is Tri-State\n"
                  f"the pin direction is: {temp}\n"
                  f"the .direction is {bin(self.gpio().direction)}\n"
                  f"the .value is {bin(new_pins_states)}")
            raise

        self.options['initial'] = new_pins_states
        return (new_pins_states >> gpio_position) & 1

    def gpio_tristate_val(self, pin: int = 0) -> bool:
        """gpio(pin)
        0 = C232HM dongle BROWN WIRE - AKA CS
        1 = C232HM dongle GREY WIRE - AKA GPIOL0
        2 = C232HM dongle PURPLE WIRE - AKA GPIOL1
        3 = C232HM dongle WHITE WIRE - AKA GPIOL3

        Args:
            pin (int): gpio pin

        Returns:
            bool: pin tristate mode, True = Tristate
        """
        if pin < 0:
            print(f"invalid pin #{pin}, use 3-0, used: 0")
            pin = 0
        elif pin > 3:
            print(f"invalid pin #{pin}, use 3-0, used: 3")
            pin = 3
        gpio_position = pin + 3  # bit number 3
        all_pins_direction = self.gpio().direction
        # 1 is driven, 0 is tristate
        self.options['direction'] = all_pins_direction & self.gpio_master_mask
        return not ((all_pins_direction >> gpio_position) & 1)

    def set_gpio_tristate_val(self, pin: int = 0,
                              tristate: bool = True, **kwargs) -> bool:
        """gpio0(pin, tristate)
        0 = C232HM dongle BROWN WIRE - AKA CS
        1 = C232HM dongle GREY WIRE - AKA GPIOL0
        2 = C232HM dongle PURPLE WIRE - AKA GPIOL1
        3 = C232HM dongle WHITE WIRE - AKA GPIOL3

        Args:
            tristate (bool, optional): [description]. Defaults to True.

        Returns:
            bool: Tristate Value, True = Tristate
        """
        if pin < 0:
            print(f"invalid pin #{pin}, use 3-0, used: 0")
            pin = 0
        elif pin > 3:
            print(f"invalid pin #{pin}, use 3-0, used: 3")
            pin = 3
        gpio_position = pin + 3  # bit number 3
        pin_mask = 1 << gpio_position
        pins = self.gpio().pins  # usually returns 0xFF78, that's all of
        #                          the usable in 16-bit
        all_pins_direction = self.gpio().direction
        pin_tristate = not ((all_pins_direction >> gpio_position) & 1)
        if tristate and pin_tristate:  # Want pin tristate (direction=0)
            return  # it already is
        elif tristate:
            # Note: direction == 0 is input
            new_pin_direction = all_pins_direction & ~pin_mask
            # If it is not tristate yet and is driven high, we need
            # to drive it to low after setting it tristate to avoid
            # leaving the old driven state in the buffer.
            # possibly a bug in pyftdi related to this?
            # self.gpio().set_direction(pins, new_pin_direction,
            #                           immediate=True)
            self.gpio().set_direction(pins, new_pin_direction, **kwargs)
            # does NOT
            #                                                   change output
            # self.set_gpio_val(pin, False)  # drive it low to set tristate
        else:  # Want the pin driven mode
            # Note: direction == 1 is output
            new_pin_direction = all_pins_direction | pin_mask  # flip the bit
            # self.gpio().set_direction(pins, new_pin_direction,
            #                           immediate=True)
            self.gpio().set_direction(pins, new_pin_direction, **kwargs)
            # does NOT
            #                                                   change output
            # self.set_gpio_val(pin, self.gpio_val(pin))  # drive to last state
        all_pins_direction = self.gpio().direction
        self.options['direction'] = all_pins_direction
        return not ((all_pins_direction >> gpio_position) & 1)

    def gpio_0_val(self) -> bool:
        return self.gpio_val(0)

    def set_gpio_0_val(self, state: bool = False, **kwargs) -> bool:
        return self.set_gpio_val(0, state, **kwargs)

    def gpio_0_tristate_val(self) -> bool:
        return self.gpio_tristate_val(0)

    def set_gpio_0_tristate_val(self, tristate: bool = False,
                                **kwargs) -> bool:
        return self.set_gpio_tristate_val(0, tristate, **kwargs)

    def gpio_1_val(self) -> bool:
        return self.gpio_val(1)

    def set_gpio_1_val(self, state: bool = False, **kwargs) -> bool:
        return self.set_gpio_val(1, state, **kwargs)

    def gpio_1_tristate_val(self) -> bool:
        return self.gpio_tristate_val(1)

    def set_gpio_1_tristate_val(self, tristate: bool = False,
                                **kwargs) -> bool:
        return self.set_gpio_tristate_val(1, tristate, **kwargs)

    def gpio_2_val(self) -> bool:
        return self.gpio_val(2)

    def set_gpio_2_val(self, state: bool = False, **kwargs) -> bool:
        return self.set_gpio_val(2, state, **kwargs)

    def gpio_2_tristate_val(self) -> bool:
        return self.gpio_tristate_val(2)

    def set_gpio_2_tristate_val(self, tristate: bool = False,
                                **kwargs) -> bool:
        return self.set_gpio_tristate_val(2, tristate, **kwargs)

    def gpio_3_val(self) -> bool:
        return self.gpio_val(3)

    def set_gpio_3_val(self, state: bool = False, **kwargs) -> bool:
        return self.set_gpio_val(3, state, **kwargs)

    def gpio_3_tristate_val(self) -> bool:
        return self.gpio_tristate_val(3)

    def set_gpio_3_tristate_val(self, tristate: bool = False,
                                **kwargs) -> bool:
        return self.set_gpio_tristate_val(3, tristate, **kwargs)

    # data formatting related methods
    @staticmethod
    def bytes2uint(byte_array, split_bytes: bool = False, endian='little'):
        """
        bytes2uint(byte_array, split_bytes: bool = False, endian='little')

        Converts a byte array of arbitrary length to an unsigned integer. Byte
        order can be specified with the "endian" arguement. Byte array can
        optionally be returns as a tuple of integers corresponding with each
        byte.

        Args:
            byte_array (bytes, bytearray): byte array to convert
            split_bytes (bool, optional): Whether to split "byte_array:" into a
                                          tuple of bytes (True) or interpret
                                          the value as a single unsigned
                                          integer (False). Defaults to False.
            endian (str, optional): [description]. Defaults to 'little'.

        Returns:
            [type]: [description]
        """

        n = len(byte_array)

        if n < 1:
            return None
        elif n == 1:
            return struct.unpack('B', byte_array)[0]

        endian = endian.lower()
        end_char = '<' if endian == 'little' else '>'

        if split_bytes:
            return tuple(struct.unpack(end_char + 'B'*n, byte_array))

        if n == 2:
            return struct.unpack(f'{end_char}H', byte_array)[0]
        elif n == 4:
            return struct.unpack(f'{end_char}I', byte_array)[0]

        # handles arbitrary lengths
        acc = 0
        for i, b in enumerate(struct.unpack(end_char + 'B'*n, byte_array)):
            acc += b << ((8*i) if endian == 'little' else (8*(n - i - 1)))
        return acc

    @staticmethod
    def uint2bytes(value: int, n_bytes: int, endian: str = 'little'):
        """
        uint2bytes(value: int, n_bytes: int, endian='little')

        Converts a non-negative integer into a bytearray of a specified length.
        Values that required a greater number of bytes to represent than what
        is specified will be truncated while values that can be represented in
        a smaller number bytes than the specified amount will be 0-padded

        Args:
            value (int): unsigned integer to convert
            n_bytes (int): number of bytes in the output byte-array
            endian (str, optional): byte-order. Valid options are 'little'
                                    (LSB first) and 'big' (MSB first). Defaults
                                    to 'little'.

        Raises:
            ValueError: raised if a negative integer or other datatype is
                        passed through value. Or alternatively if an invalid
                        option for 'endian' is used.

        Returns:
            bytearray: the integer "value" stored in a byte-array with the
                       specified length and order.
        """

        if not (isinstance(value, int) and (value >= 0)):
            raise ValueError('Function can only convert positive integers')

        endian = endian.lower()
        end_char = '<' if endian == 'little' else '>'

        if endian == 'little':
            gen = ((value >> (8*i)) & 255 for i in range(n_bytes))
        elif endian == 'big':
            gen = ((value >> (8*i)) & 255 for i in range(n_bytes - 1, -1, -1))
        else:
            raise ValueError('Invalid value for kwarg "endian"')

        byte_array = struct.pack(f"{end_char}{'B'*n_bytes}", *gen)
        return byte_array

    @staticmethod
    def twos_complement(value: int, n_bits: int, reverse=False):
        """
        twos_complement(value, n_bits, reverse=False)

        Converts integers between two's complement and signed-integer formats.
        arbitrary bit lengths are supported by specifying the bit length
        (n_bits).

        Args:
            value (int): twos complent or signed integer value to convert
            n_bits (int): number of bits that constitue a packet
            reverse (bool, optional): whether to convert from twos complement
                    to signed (False) or from signed twos complement (True).
                    Defaults to False.

        Returns:
            int: converted value
        """

        if reverse:
            return (value + (1 << n_bits)) % (1 << n_bits)

        if (value & (1 << (n_bits - 1))) != 0:
            return value - (1 << n_bits)
        return value

    @classmethod
    def decode_lin11(cls, value: int):

        """
        decode_lin11(val)

        Decodes a "linear 11" formatted integer into a floating point number.
        The Linear 11 encoding scheme is similar to the floating point standard
        its structure is shown below:

        MSB                             LSB
        [   EXP   ][       MANTISSA       ]
        |<----      WORD LENGTH      ---->|

        Where the 2 byte word consists of a 5 bit exponent and an 11 bit
        mantissa. Both the mantissa and exponent are stored as two's complement
        numbers. The resulting float is calculated as:

        float = mantissa*(2^exponent)

        After converting the mantissa and exponent from twos complement to
        signed integers.

        Arguments:
            value {int} -- linear 11 formatted integer

        Returns:
            out {float} -- decoded value
        """
        return cls.extract_lin11(value=value)[2]

    @classmethod
    def extract_lin11(cls, value: int) -> "tuple(int, int, float)":
        """
        extract_lin11(val)

        Extracts a "linear 11" formatted integer into a its components of
        exponent, mantissa and si units floating point number.
        The Linear 11 encoding scheme is similar to the floating point standard
        its structure is shown below:

        MSB                             LSB
        [   EXP   ][       MANTISSA       ]
        |<----      WORD LENGTH      ---->|

        Where the 2 byte word consists of a 5 bit exponent and an 11 bit
        mantissa. Both the mantissa and exponent are stored as two's complement
        numbers. The resulting float is calculated as:

        float = mantissa*(2^exponent)

        After converting the mantissa and exponent from twos complement to
        signed integers.

        Arguments:
            value {int} -- linear 11 formatted integer

        Returns:
            tuple [int, int, float]: decoded value as exponent, mantissa, si
        """

        exp = (value & 0xf800) >> 11
        exp = cls.twos_complement(exp, 5)

        mantissa = value & 0x07ff
        mantissa = cls.twos_complement(mantissa, 11)

        si_float = float(mantissa*(2**exp))

        return (exp, mantissa, si_float)

    @classmethod
    def encode_lin11(cls, value: float, exp: int):

        """
        encode_lin11(val)

        Encodes a floating point number into a "linear 11" formatted integer.
        The Linear 11 encoding scheme is similar to the floating point standard
        its structure is shown below:

        MSB                             LSB
        [   EXP   ][       MANTISSA       ]
        |<----      WORD LENGTH      ---->|

        Where the 2 byte word consists of a 5 bit exponent and an 11 bit
        mantissa. Both the mantissa and exponent are stored as two's complement
        numbers. The resulting integer is calculated as:

        out = (Twos{exp} << 11) | Twos{(value * 2^-exp)}

        where 'Twos{x}' denotes converting x to a twos complement number

        Arguments:
            value {float} -- value to encode

            exp {int}  -- exponent to be use for encoding, this can differ
                          between firmware as well as between each signal.

        Returns:
            out {int} -- encoded linear 11 formatted integer
        """

        formatted_exp = cls.twos_complement(exp, 5, reverse=True)
        formatted_mant = 0x7FF & round(cls.twos_complement(value*(2**-exp),
                                                           11, reverse=True))

        return ((formatted_exp << 11) | (formatted_mant))

    @staticmethod
    def decode_ulin16(value: int, exponent: int = -9) -> float:
        """
        decode_ulin16(value)

        Decodes an "unsigned linear 16" formatted integer into a floating point
        number. The structure of the unsigned linear 16 encoding scheme is
        shown below:

        MSB                                LSB
        [ INTEGER PART ][   FRACTIONAL PART  ]
        |<-------     WORD LENGTH    ------->|

        Where the 2 byte word consists of a 7 bit integer part and an
        [exponent] bit fractional part. Both parts are stored as
        unsigned integers. The resulting float is calculated as:

        float = value*(2^(-9))

        Arguments:
            value {int} -- integer value to decode

        Returns:
            out {float} -- decoded value
        """

        return value*(2**exponent)

    @staticmethod
    def encode_ulin16(value: float, exponent: int = -9) -> int:
        """
        encode_ulin16(value)

        Encodes a floating point number  into an "unsigned linear 16" formatted
        integer number. The structure of the unsigned linear 16 encoding scheme
        is shown below:

        MSB                                LSB
        [ INTEGER PART ][   FRACTIONAL PART  ]
        |<-------     WORD LENGTH    ------->|

        Where the 2 byte word consists of a 7 bit integer part and an
        [exponent] bit fractional part. Both parts are stored as
        unsigned integers. The resulting integer is calculated as:

        ulin16 = int(value/(2^(-9)))

        Arguments:
            value -- float value to encode

        Returns:
            out {int} -- encoded ulin16 integer value
        """

        return round(value/(2**exponent))

    @staticmethod
    def auto_encode_lin11(value, exponent: int = None, verbose=False) -> int:
        """auto_encode_lin11 creates a linear11 integer, two bytes unsigned
        which picks the exponent that provides the most resolution

        Args:
            value (float): SI units number to convert to linear11 format
            exponent (int, optional): exponent to use if possible. Will use as
            close a value as possible to this exponent in future version.
            Defaults to None.
            verbose (bool, optional): if True will print the linear11 integer,
            the twos complement exponent integer and the mantissa integer.
            Defaults to False.

        Returns:
            int: linear11 encoded value, two bytes unsigned
        """
        if value == 0:
            logbits = 0
        else:
            logbits = log(abs(value), 2)
        logbit = int(ceil(logbits))
        bits_avail = int(10)
        exponent = logbit - bits_avail
        mantissa = floor(value * 2**(-exponent))

        twos_exponent = Use_Ftdi.twos_complement(exponent, 5, reverse=True)
        shifted_twos_exponent = twos_exponent << 11
        linear11 = int(mantissa + shifted_twos_exponent)

        if verbose:
            print(f'linear11 is: {linear11}')
            print(f'twos_exponent is: {twos_exponent}')
            print(f'mantissa is: {mantissa}')

        return linear11


def get_available_ftdi_urls():
    """
    get_available_ftdi_urls()

    Prints all availible FTDI interfaces currently connected to the machine.

    Returns: List: List of Tuples for each ftdi connection found. Tuples are
                   returned as (url, description) pairs.
    """

    io_buffer = StringIO()
    with redirect_stdout(io_buffer):
        Ftdi.show_devices()  # normally prints to stdout and returns None
    response = io_buffer.getvalue()

    # parse out list of connected devices
    response = response.lstrip('Available interfaces:').strip()

    connections = []
    for connection in response.split('\n'):
        if connection == '':
            continue
        url, desc = connection.split()
        desc = desc.replace('(', '').replace(')', '')
        connections.append((url, desc))

    if not connections:
        raise IOError("No FTDI devices found. Check USB connections..."
                      " Restart python to try again.")

    return connections


def init_ftdi(ftdinum: int = None, prompt: bool = False, **kwargs):
    """init_ftdi(**kwargs)

    Args:
        kwargs (dict): setup frequency, clockstretching, and gpio
                       initial and direction settings
                       Defaults: {'frequency': int(400000),
                       'clockstretching': True,
                       'initial': 0x78, 'direction': 0x78}
        ftdinum (int): which dongle to use, if not provided function will ask
                       for user input if multiple FTDI found in system
                       note that if a large number is given, highest order ftdi
                       is selected, example: 99 when 2 ftdi present uses #2

    Raises:
        IOError: If no FTDI connection working at selected address
        IndexError: If no FTDI dongles are found connected to system

    Returns:
        i2c: FTDI instance ready for additional operations
        gpio: FTDI instance gpio handle
    """

    try:
        i2cURLs = get_available_ftdi_urls()
        # ...urls()[dongle position in the list, 0 if only one][dongle url is
        #                                                       element 0]
    except IndexError:
        raise IOError("No FTDI Devices Found, plugged in? Check USB"
                      " connections... If it is plugged in, did you"
                      " change the driver for THIS dongle?")

    # ftdi_options = {'frequency': int(400000), 'clockstretching': True,
    #                 'initial': 0x78, 'direction': 0x78}
    if kwargs:
        ftdi_options = kwargs
    else:
        ftdi_options = {'frequency': int(400000), 'clockstretching': True,
                        'initial': 0x78, 'direction': 0x78}

    if len(i2cURLs) > 1 and prompt:
        if ftdinum is None:
            print("found multiple FTDI: "
                  f"{i2cURLs}")
            ftdinum = int(input("More than one FTDI Device "
                                "found, choose device by "
                                "list number where 0 is "
                                f"{i2cURLs[0][0]}: "))
        if ftdinum > (len(i2cURLs) - 1):
            ftdinum = (len(i2cURLs) - 1)
    else:
        ftdinum = 0
    print(f"FTDI address [{ftdinum}] = {i2cURLs[ftdinum][0]} selected")

    # make an instance of the i2c dongle and hunt for addresses
    try:
        i2c = Use_Ftdi(ftdi=i2cURLs[ftdinum][0], **ftdi_options)
    except FtdiError:
        input("is there an i2c device connected or powered? press any key to"
              " retry...I2C_SCL could be stuck low.")
        try:
            i2c = Use_Ftdi(ftdi=i2cURLs[ftdinum][0], **ftdi_options)
        except FtdiError:
            raise IOError("Retry failed, Unable to connect to an FTDI"
                          " interface. Check USB and I2C device connections")

    gpio = i2c.gpio()

    return i2c, gpio


def find_device(i2c, devlib, device=None, addr_list_offset: int = 0,
                verbose: bool = False, silent: bool = False):
    """find_device(i2c, devlib)
    Args:
        i2c (ftdi instance): FTDI dongle instance
        devlib (ftdi class): FTDI dongle library for target device type
        device (instance, optional): i2c device that you need to move.
        Defaults to None.
        addr_list_offset (int, optional): if there are multiple devices on the
                                          i2c bus, use this to grab one other
                                          than the first, Defaults to 0.
                                          very large values pick last item
    Returns:
        [instance, device]: instance of your i2c device at address
        [list]: list of all found i2c devices on the bus
    """
    kwargs = i2c.options

    i2c_device_list = i2c.find_i2c_devices(verbose=verbose, show_nack=False)
    if i2c_device_list == []:
        print("first pass finding devices failed, wait and retry...")
        time.sleep(0.05)
        i2c_device_list = i2c.find_i2c_devices(verbose=True,
                                               show_nack=False)

    if len(i2c_device_list) <= 1:
        addr_list_offset = 0
    else:
        if addr_list_offset >= len(i2c_device_list):
            addr_list_offset = len(i2c_device_list) - 1
            # this is a quick error hanlding, so if you want the last
            # item on the list, put in a huge value, you'll stop at
            # the end of the list.. example, two items, offset = 99

    if device is None:
        try:
            device = devlib(i2c_device_list[0+addr_list_offset], ftdi=i2c,
                            **kwargs)
        except IndexError:
            raise IOError("its broken again... what do captain?")
        #  device.i2c_master.flush()
        if verbose:
            print((f'new address: {i2c_device_list[0+addr_list_offset]},'
                   f'instance: {device}'))
    elif isinstance(device, devlib):  # device is an instance of devlib already
        try:
            address = device.pmbus_addr
        except AttributeError:
            address = None  # this should never happen...?

        if address != i2c_device_list[0+addr_list_offset]:
            device.set_address(i2c_device_list[0+addr_list_offset])
            if verbose:
                print(f'new address..., instance: {device}')
                print(f'ftdi options are: {device.options}')
        else:
            if verbose:
                print(f'existing address..., instance: {device}')
                print(f'ftdi options are: {device.options}')
    else:
        raise IOError("device or devlib is wrong type?? Try again...")

    try:
        device.read_slave(0)
        if not silent and not verbose:
            print(f"new address: {i2c_device_list[0+addr_list_offset]}")
    except I2cIOError:
        raise IOError("why dont it workie?")
        device.i2c_master.flush()
    return device, i2c_device_list


def toNametuple(dict_data) -> namedtuple:
    return namedtuple("X", dict_data.keys())(*tuple(map(
        lambda x: x if not isinstance(x, dict) else toNametuple(x),
        dict_data.values())))


if __name__ == "__main__":
    pass
