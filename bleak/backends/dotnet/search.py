# -*- coding: utf-8 -*-
"""
Perform advanced Bluetooth LE Scan.

Created on 2019-03-26 by bojanpotocnik <info@bojanpotocnik.com>

"""
import asyncio
import datetime
import enum
import logging
import os
import re
import threading
# noinspection PyCompatibility
from dataclasses import dataclass
from typing import List, Optional, Union, Pattern, MutableSequence, Dict, AsyncIterable
from asyncio.events import AbstractEventLoop

from bleak.backends.device import BLEDevice
from bleak.uuids import ble_uuid_to_128bit

# Import of Bleak CLR->UWP Bridge. It is not needed here, but it enables loading of Windows.Devices
# noinspection PyUnresolvedReferences
from BleakBridge import Bridge  # noqa: F401

# noinspection PyUnresolvedReferences,PyPackageRequirements
from System import Array, Byte

# noinspection PyUnresolvedReferences,PyPackageRequirements
from Windows.Devices.Bluetooth.Advertisement import (BluetoothLEAdvertisementWatcher,
                                                     BluetoothLEScanningMode,
                                                     BluetoothLEAdvertisementReceivedEventArgs,
                                                     BluetoothLEAdvertisement,
                                                     BluetoothLEManufacturerData,
                                                     BluetoothLEAdvertisementDataSection,
                                                     BluetoothLEAdvertisementWatcherStoppedEventArgs)
# noinspection PyUnresolvedReferences,PyPackageRequirements
from Windows.Storage.Streams import DataReader, IBuffer

logger = logging.getLogger(__name__)


# noinspection SpellCheckingInspection
@enum.unique
class GAPDataType(enum.IntEnum):
    """
    `Assigned numbers <https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile>`_
    are used in Generic Access Profile for inquiry response, EIR data type values, manufacturer-specific
    data, advertising data, low energy UUIDs and appearance characteristics, and class of device.
    """

    Flags = 0x01
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.3 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.3 and 18.1 (v4.0)
    Core Specification Supplement, Part A, section 1.3
    """
    Incomplete_List_of_16bit_Service_Class_UUIDs = 0x02
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.1 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.1 and 18.2 (v4.0)
    Core Specification Supplement, Part A, section 1.1
    """
    Complete_List_of_16bit_Service_Class_UUIDs = 0x03
    """Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.1 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.1 and 18.2 (v4.0)
    Core Specification Supplement, Part A, section 1.1
    """
    Incomplete_List_of_32bit_Service_Class_UUIDs = 0x04
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.1 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, section 18.2 (v4.0)
    Core Specification Supplement, Part A, section 1.1
    """
    Complete_List_of_32bit_Service_Class_UUIDs = 0x05
    """Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.1 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, section 18.2 (v4.0)
    Core Specification Supplement, Part A, section 1.1
    """
    Incomplete_List_of_128bit_Service_Class_UUIDs = 0x06
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.1 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.1 and 18.2 (v4.0)
    Core Specification Supplement, Part A, section 1.1
    """
    Complete_List_of_128bit_Service_Class_UUIDs = 0x07
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.1 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.1 and 18.2 (v4.0)
    Core Specification Supplement, Part A, section 1.1
    """
    Shortened_Local_Name = 0x08
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.2 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.2 and 18.4 (v4.0)
    Core Specification Supplement, Part A, section 1.2
    """
    Complete_Local_Name = 0x09
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.2 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.2 and 18.4 (v4.0)
    Core Specification Supplement, Part A, section 1.2
    """
    Tx_Power_Level = 0x0A
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.5 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.5 and 18.3 (v4.0)
    Core Specification Supplement, Part A, section 1.5
    """
    Class_of_Device = 0x0D
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.6 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.5 and 18.5 (v4.0)
    Core Specification Supplement, Part A, section 1.6
    """
    Simple_Pairing_Hash_C192 = 0x0E
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.6 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.5 and 18.5 (v4.0)
    Core Specification Supplement, Part A, section 1.6
    """
    Simple_Pairing_Randomizer_R192 = 0x0F
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.6 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.5 and 18.5 (v4.0)
    Core Specification Supplement, Part A, section 1.6
    """
    Device_ID_or_Security_Manager_TK_Value = 0x10
    """
    Device ID Profile v1.3 or later
    or
    Bluetooth Core Specification:
    Vol. 3, Part C, sections 11.1.7 and 18.6 (v4.0)
    Core Specification Supplement, Part A, section 1.8
    """
    Security_Manager_Out_of_Band_Flags = 0x11
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, sections 11.1.6 and 18.7 (v4.0)
    Core Specification Supplement, Part A, section 1.7
    """
    Slave_Connection_Interval_Range = 0x12
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, sections 11.1.8 and 18.8 (v4.0)
    Core Specification Supplement, Part A, section 1.9
    """
    List_of_16bit_Service_Solicitation_UUIDs = 0x14
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, sections 11.1.9 and 18.9 (v4.0)
    Core Specification Supplement, Part A, section 1.10
    """
    List_of_128bit_Service_Solicitation_UUIDs = 0x15
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, sections 11.1.9 and 18.9 (v4.0)
    Core Specification Supplement, Part A, section 1.10
    """
    Service_Data_16bit_UUID = 0x16
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, sections 11.1.10 and 18.10 (v4.0)
    Core Specification Supplement, Part A, section 1.11
    """
    Public_Target_Address = 0x17
    """Bluetooth Core Specification: Core Specification Supplement, Part A, section 1.13"""
    Random_Target_Address = 0x18
    """Bluetooth Core Specification: Core Specification Supplement, Part A, section 1.14"""
    Appearance = 0x19
    """Bluetooth Core Specification: Core Specification Supplement, Part A, section 1.12"""
    Advertising_Interval = 0x1A
    """Bluetooth Core Specification: Core Specification Supplement, Part A, section 1.15"""
    LE_Bluetooth_Device_Address = 0x1B
    """Core Specification Supplement, Part A, section 1.16"""
    LE_Role = 0x1C
    """Core Specification Supplement, Part A, section 1.17"""
    Simple_Pairing_Hash_C256 = 0x1D
    """Core Specification Supplement, Part A, section 1.6"""
    Simple_Pairing_Randomizer_R256 = 0x1E
    """Core Specification Supplement, Part A, section 1.6"""
    List_of_32bit_Service_Solicitation_UUIDs = 0x1F
    """Core Specification Supplement, Part A, section 1.10"""
    Service_Data_32bit_UUID = 0x20
    """Core Specification Supplement, Part A, section 1.11"""
    Service_Data_128bit_UUID = 0x21
    """Core Specification Supplement, Part A, section 1.11"""
    LE_Secure_Connections_Confirmation_Value = 0x22
    """Core Specification Supplement Part A, Section 1.6"""
    LE_Secure_Connections_Random_Value = 0x23
    """Core Specification Supplement Part A, Section 1.6"""
    URI = 0x24
    """Bluetooth Core Specification: Core Specification Supplement, Part A, section 1.18"""
    Indoor_Positioning = 0x25
    """Indoor Positioning Service v1.0 or later"""
    Transport_Discovery_Data = 0x26
    """Transport Discovery Service v1.0 or later"""
    LE_Supported_Features = 0x27
    """Core Specification Supplement, Part A, Section 1.19"""
    Channel_Map_Update_Indication = 0x28
    """Core Specification Supplement, Part A, Section 1.20"""
    PB_ADV = 0x29
    """Mesh Profile Specification Section 5.2.1"""
    Mesh_Message = 0x2A
    """Mesh Profile Specification Section 3.3.1"""
    Mesh_Beacon = 0x2B
    """Mesh Profile Specification Section 3.9"""
    Information_Data_3D = 0x3D
    """3D Synchronization Profile, v1.0 or later"""
    Manufacturer_Specific_Data = 0xFF
    """
    Bluetooth Core Specification:
    Vol. 3, Part C, section 8.1.4 (v2.1 + EDR, 3.0 + HS and 4.0)
    Vol. 3, Part C, sections 11.1.4 and 18.11 (v4.0)
    Core Specification Supplement, Part A, section 1.4
    """


@enum.unique
class AdvertisementType(enum.IntEnum):
    """
    `AdvertisementType
    <https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementtype>`_
    enum specifies the different types of Bluetooth LE advertisement payloads.
    """

    CONNECTABLE_DIRECTED = 1
    """
    The advertisement is directed and indicates that the device is connectable but not scannable.
    This advertisement type cannot carry data.
    This corresponds with the ADV_DIRECT_IND type defined in the Bluetooth LE specifications.
    """
    CONNECTABLE_UNDIRECTED = 0
    """
    The advertisement is undirected and indicates that the device is connectable and scannable.
    This advertisement type can carry data.
    This corresponds with the ADV_IND type defined in the Bluetooth LE specifications.
    """
    NON_CONNECTABLE_UNDIRECTED = 3
    # noinspection SpellCheckingInspection
    """
    The advertisement is undirected and indicates that the device is not connectable nor scannable.
    This advertisement type can carry data.
    This corresponds with the ADV_NONCONN_IND type defined in the Bluetooth LE specifications.
    """
    SCANNABLE_UNDIRECTED = 2
    """
    The advertisement is undirected and indicates that the device is scannable but not connectable.
    This advertisement type can carry data.
    This corresponds with the ADV_SCAN_IND type defined in the Bluetooth LE specifications.
    """
    SCAN_RESPONSE = 4
    """
    This advertisement is a scan response to a scan request issued for a scannable advertisement.
    This advertisement type can carry data.
    This corresponds with the SCAN_RSP type defined in the Bluetooth LE specifications.
    """


@dataclass(init=False)
class Advertisement:
    """`BluetoothLEAdvertisement
    <https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisement>`_
    class represents a Bluetooth LE advertisement payload data received.
    """

    @dataclass(init=False)
    class DataSection:
        """
        `BluetoothLEAdvertisementDataSection
        <https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementdatasection>`_
        class specifies a Bluetooth LE advertisement section. A Bluetooth LE advertisement
        packet can contain multiple instances of these objects.
        """
        data: bytes
        """The Bluetooth LE advertisement data payload."""
        data_type: GAPDataType
        """The `Bluetooth LE advertisement data type
         <https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile>`_
         as defined by the Bluetooth Special Interest Group (SIG)."""

        def __init__(self, ds: BluetoothLEAdvertisementDataSection) -> None:
            self.data_type = GAPDataType(ds.DataType)
            # Read bytes from IBuffer type
            reader = DataReader.FromBuffer(IBuffer(ds.Data))
            output = Array[Byte]([0] * reader.UnconsumedBufferLength)
            self.data = bytes(reader.ReadBytes(output))

        def __str__(self) -> str:
            return "{}({}, 0x{})".format(type(self).__name__, self.data_type.name, self.data.hex())

    class Flags(enum.IntFlag):
        """
        `BluetoothLEAdvertisementFlags
        <https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementflags>`_
        enum specifies flags used to match flags contained inside a Bluetooth LE advertisement payload.
        """
        CLASSIC_NOT_SUPPORTED = 4
        """Bluetooth BR/EDR not supported."""
        DUAL_MODE_CONTROLLER_CAPABLE = 8
        """Simultaneous Bluetooth LE and BR/EDR to same device capable (controller)."""
        DUAL_MODE_HOST_CAPABLE = 16
        """Simultaneous Bluetooth LE and BR/EDR to same device capable (host)."""
        GENERAL_DISCOVERABLE_MODE = 2
        """Bluetooth LE General Discoverable Mode."""
        LIMITED_DISCOVERABLE_MODE = 1
        """Bluetooth LE Limited Discoverable Mode."""

    @dataclass(init=False)
    class ManufacturerData:
        """`BluetoothLEManufacturerData
        <https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothlemanufacturerdata>`_
        represents a Bluetooth LE manufacturer-specific data section (one
        particular type of LE advertisement section).
        """

        company_id: int
        """The `Bluetooth LE company identifier code
        <https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers>`_
         as defined by the Bluetooth Special Interest Group (SIG)."""
        data: bytes
        """Bluetooth LE manufacturer-specific section data."""

        def __init__(self, data: BluetoothLEManufacturerData) -> None:
            self.company_id = data.CompanyId
            # Read bytes from IBuffer type
            reader = DataReader.FromBuffer(IBuffer(data.Data))
            output = Array[Byte]([0] * reader.UnconsumedBufferLength)
            self.data = bytes(reader.ReadBytes(output))

        def __str__(self) -> str:
            return "{}(0x{:04x}, 0x{})".format(type(self).__name__, self.company_id, self.data.hex())

    data_sections: List[DataSection]
    """The list of raw data sections."""
    flags: Optional[Flags]
    """Bluetooth LE advertisement flags."""
    local_name: str
    """The local name contained within the advertisement."""
    manufacturer_data: List[ManufacturerData]
    """The list of manufacturer-specific data sections."""
    services: List[str]
    """The list of service UUIDs in 128-bit GUID format in a BluetoothLEAdvertisement."""
    appearance: Optional[int] = None
    """
    16-bit device appearance value as `defined by SIG
    <https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.characteristic.gap.appearance.xml>`_.
    """
    tx_power_level: Optional[int] = None
    """Device TX power level in dBm."""

    def __init__(self, args: BluetoothLEAdvertisement) -> None:
        self.data_sections = [self.DataSection(ds) for ds in args.DataSections]
        self.flags = self.Flags(args.Flags) if args.Flags else None
        self.local_name = args.LocalName
        self.manufacturer_data = [self.ManufacturerData(md) for md in args.ManufacturerData]
        self.services = [su.ToString() for su in args.ServiceUuids]
        # Parse known data sections
        for ds in self.data_sections:
            if ds.data_type == GAPDataType.Appearance:
                self.appearance = int.from_bytes(ds.data, 'big')
            elif ds.data_type == GAPDataType.Tx_Power_Level:
                self.tx_power_level = int.from_bytes(ds.data, 'big')

    def __str__(self) -> str:
        s = "{}('{}'".format(type(self).__name__, self.local_name)
        if self.appearance is not None:
            s += ", appearance=0x{:04x}".format(self.appearance)
        if self.tx_power_level is not None:
            s += ", tx_power_level={} dBm".format(self.tx_power_level)
        if self.flags is not None:
            s += ", flags={}".format(str(self.flags))
        if self.data_sections:
            # Some data sections are parsed separately
            sections = [ds for ds in self.data_sections if ds.data_type not in (
                GAPDataType.Flags,  # Advertisement.flags
                GAPDataType.Complete_Local_Name, GAPDataType.Shortened_Local_Name,  # Advertisement.local_name
                GAPDataType.Manufacturer_Specific_Data,  # Advertisement.manufacturer_data
                GAPDataType.Appearance,  # Advertisement.appearance
                GAPDataType.Tx_Power_Level,  # Advertisement.tx_power_level
                GAPDataType.Complete_List_of_16bit_Service_Class_UUIDs  # Advertisement.services
            )]
            if sections:
                s += ",\r\n\t" + ", ".join(str(ds) for ds in sections)
        if self.manufacturer_data:
            s += ",\r\n\t" + ", ".join(str(md) for md in self.manufacturer_data)
        if self.services:
            s += ",\r\n\tservices=" + str(self.services)
        return s + "\r\n)"


@dataclass(init=False)
class AdvertisementReceivedEventArgs:
    """
    Python representation of the `BluetoothLEAdvertisementReceivedEventArgs
    <https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementreceivedeventargs>`_
    class for type checking and easier coding.
    """

    advertisement: Advertisement
    """The Bluetooth LE advertisement payload data received."""
    advertisement_type: AdvertisementType
    """The type of the received Bluetooth LE advertisement packet."""
    bluetooth_address: str
    """The Bluetooth address of the device sending the Bluetooth LE advertisement."""
    raw_signal_strength_in_dBm: int
    # noinspection SpellCheckingInspection
    """
    The received signal strength indicator (RSSI) value, in dBm, for this event.
    This value could be the raw RSSI or a filtered RSSI depending on filtering
    settings configured through BluetoothSignalStrengthFilter.
    """
    timestamp: datetime.datetime
    """The timestamp when the Received event occurred."""

    def __init__(self, args: BluetoothLEAdvertisementReceivedEventArgs) -> None:
        self.advertisement = Advertisement(args.Advertisement)
        # AdvertisementType is an enum.
        self.advertisement_type = AdvertisementType(args.AdvertisementType)
        # Convert MAC address from 64-bit integer to string representation of MAC address.
        mac_str = "{:012x}".format(args.BluetoothAddress).upper()
        self.bluetooth_address = ":".join(mac_str[i:i + 2] for i in range(0, len(mac_str), 2))
        # Raw signal is integer.
        self.raw_signal_strength_in_dBm = args.RawSignalStrengthInDBm
        # Timestamp is DateTimeOffset structure. It could be converted to
        # "Round-trip date/time pattern" using "o" specifier and then parsed
        # using datetime.datetime.fromisoformat(), but this is Python >=3.7 only.
        # Keep the proper timezone information.
        t = args.Timestamp
        self.timestamp = datetime.datetime(
            year=t.Year, month=t.Month, day=t.Day,
            hour=t.Hour, minute=t.Minute, second=t.Second, microsecond=1000 * t.Millisecond,
            tzinfo=datetime.timezone(datetime.timedelta(hours=t.Offset.Hours)))

    def __str__(self) -> str:
        return ("{}({}, {} dBm, {:%H:%m:%S}.{:03.0f}, {},\r\n"
                "\tadvertisement={}\r\n"
                ")").format(
            type(self).__name__,
            self.bluetooth_address, self.raw_signal_strength_in_dBm,
            self.timestamp, self.timestamp.microsecond / 1000,
            self.advertisement_type.name,
            # Add additional \t in front of each new line.
            "\r\n\t".join(str(self.advertisement).split("\r\n"))
        )


@enum.unique
class AdvertisementWatcherStatus(enum.IntEnum):
    """
    `BluetoothLEAdvertisementWatcherStatus
    <https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementwatcherstatus>`_
    enum represents the possible states of the BluetoothLEAdvertisementWatcher.
    """
    Aborted = 4
    """An error occurred during transition or scanning that stopped the watcher due to an error."""
    Created = 0
    """The initial status of the watcher."""
    Started = 1
    """The watcher is started."""
    Stopped = 3
    """The watcher is stopped."""
    Stopping = 2
    """The watcher stop command was issued."""


async def find(mac: Union[None, str, Pattern] = None,
               name: Union[None, str, Pattern] = None,
               services: Optional[MutableSequence[Union[str, Pattern]]] = None,
               timeout: float = 5.0, active_scan: bool = True,
               loop: AbstractEventLoop = None) -> AsyncIterable[BLEDevice]:
    """
    Perform a Bluetooth LE Scan and locate the device matching
    the required filtering parameters.

    :param mac:  If provided as string, (only) the device fully matching this
                  MAC address will be returned. Byte separators are stripped.
                 If provided as compiled Regex pattern, all devices matching
                  this MAC pattern will be returned (note that byte separators,
                  despite mostly being ':', are best to be ignored).
                 If None, this filter is not used.
    :param name: The same rules as `mac` parameter but for device name.
    :param services: List of UUIDs of services on the device (advertised in the
                     advertising or scan response packet). The same rules as
                     `mac` or `name`. If multiple services are provided, the
                     device must provide all of them.
                     '0x' in front is ignored/stripped.
                     16-bit (4 or 6 characters, or integers) UUIDs are considered
                     SIG defined services and are converted to 128-bit UUIDs.
    :param timeout: Maximum time to scan for (seconds). If negative number then
                    the scan will stop as soon as the first device is found.
    :param active_scan: Whether to use the active scanning mode. In this mode scan
                        request packets will be sent from the platform to actively
                        query for more advertisement data (Scan Response data).

    :param loop: The event loop to use.

    :returns: Devices as soon as they are found and updated.
    """
    loop = loop or asyncio.get_event_loop()

    # BluetoothLEAdvertisementWatcher.AdvertisementFilter could be used for filtering, however filtering
    # here provides more control, enables regex filtering and more.
    # Performance impact is negligible.

    # region Check filters
    if mac:
        if isinstance(mac, str):
            # Remove any delimiters and add standard delimiters.
            mac = re.sub(r"[^A-F\d]", "", mac.upper())
            mac = ":".join(mac[i:i + 2] for i in range(0, len(mac), 2))
        elif not isinstance(mac, Pattern):
            raise TypeError(f"Invalid type {type(mac)} for MAC filter")
    if name and not isinstance(name, (str, Pattern)):
        raise TypeError(f"Invalid type {type(name)} for name filter")
    if services:
        for i, service in enumerate(services):
            # Convert SIG short 16-bit UUIDs to 128-bit UUIDs.
            try:
                services[i] = ble_uuid_to_128bit(service)
            except TypeError:
                if not isinstance(service, Pattern):
                    raise TypeError(f"Invalid type {type(service)} for service filter.")

    # endregion Check filters

    # Watcher works in the separate thread and callbacks are executed on multiple different
    # worker (Dummy) threads, therefore thread-safe containers must be used to share objects.
    devices: Dict[str, BLEDevice] = {}
    new_devices: List[BLEDevice] = []

    # region BluetoothLEAdvertisementWatcher callbacks
    def advertisement_watcher__received(_: BluetoothLEAdvertisementWatcher,
                                        args: BluetoothLEAdvertisementReceivedEventArgs):
        args = AdvertisementReceivedEventArgs(args)
        # logger.debug(f"advertisement_watcher__received(_, {args})"
        #              f" in {os.getpid()}.{threading.get_ident()}.{threading.current_thread().name}")
        device = BLEDevice(args.bluetooth_address, args.advertisement.local_name, args)
        filtered = 0

        if mac:
            if isinstance(mac, str) and (mac != args.bluetooth_address):
                logger.debug(f"Ignore, MAC {mac} != {device}.")
                return
            if isinstance(mac, Pattern) and (not mac.match(args.bluetooth_address)):
                logger.debug(f"Ignore, MAC {mac.pattern} does not match {device}.")
                return
            filtered += 1

        if name:
            if isinstance(name, str) and (name != args.advertisement.local_name):
                logger.debug(f"Ignore, name '{name}' != {device}.")
                return
            if isinstance(name, Pattern) and (not name.match(args.advertisement.local_name)):
                logger.debug(f"Ignore, name '{name.pattern}' does not match {device}.")
                return
            filtered += 1

        if services:
            if not args.advertisement.services:
                logger.debug(f"Ignore, no services in {device}.")
                return
            # noinspection PyShadowingNames
            for service in services:
                if isinstance(service, str) and (service not in args.advertisement.services):
                    logger.debug(f"Ignore, service '{service}' not in {args.advertisement.services} of {device}.")
                    return
                if isinstance(name, Pattern) and (not any(name.match(ds) for ds in args.advertisement.services)):
                    logger.debug(f"Ignore, service '{service.pattern}' does not match"
                                 f"any in {args.advertisement.services} of {device}.")
                    return
            filtered += 1

        if filtered:
            logger.debug(f"Adding {device} as it matches all filters ({filtered}).")
        else:
            logger.debug(f"Adding {device}")

        if device.address not in devices:
            devices[device.address] = device
            new_devices.append(device)
        # TODO: Handle updating of the devices in case of scan responses (what about RSSI?).

    def advertisement_watcher__stopped(_: BluetoothLEAdvertisementWatcher,
                                       __: BluetoothLEAdvertisementWatcherStoppedEventArgs):
        logger.debug(f"advertisement_watcher__stopped(_, _)"
                     f" in {os.getpid()}.{threading.get_ident()}.{threading.current_thread().name}")

    # endregion BluetoothLEAdvertisementWatcher callbacks

    # https://docs.microsoft.com/en-us/uwp/api/Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher
    watcher = BluetoothLEAdvertisementWatcher()

    def stop_scan() -> None:
        logger.debug(f"stop_scan() in {os.getpid()}.{threading.get_ident()}.{threading.current_thread().name}")
        watcher.Stop()

    # Add callbacks
    watcher.Received += advertisement_watcher__received
    watcher.Stopped += advertisement_watcher__stopped

    # Set additional watcher properties
    watcher.ScanningMode = BluetoothLEScanningMode.Active if active_scan else BluetoothLEScanningMode.Passive

    # Scanning is performed in the separate thread.
    # Start the scan and wait for watcher to start scanning.
    watcher.Start()
    while watcher.Status == AdvertisementWatcherStatus.Created.value:
        await asyncio.sleep(0.01, loop=loop)
    # Schedule scan stop after a timeout.
    loop.call_later(timeout, stop_scan)
    # Receive new devices from callbacks until the scanning is stopped.
    while watcher.Status in (AdvertisementWatcherStatus.Started.value, AdvertisementWatcherStatus.Stopping.value):
        if new_devices:
            yield new_devices.pop()
        await asyncio.sleep(0.01, loop=loop)


async def _test_find(timeout: float = 10) -> None:
    # noinspection SpellCheckingInspection
    all_kwargs: List[dict] = [
        dict(),
        dict(timeout=2),
        dict(active_scan=False),
        # name
        dict(name="Nordic_Blinky"),
        dict(name=re.compile(r".*Blinky")),
        # mac
        dict(mac="FA:BD:60:D2:11:3A"),
        dict(mac="FA:BD-60d2_113a"),
        dict(mac="FABD60D2113A"),
        dict(mac=re.compile(r"..:..:6\d:[A-Z\d]{2}:.....")),
        # services (0x180A = Device Information)
        dict(services=["0x180A"]),
        dict(services=["180A"]),
        dict(services=["0x0000180a-0000-1000-8000-00805f9b34fb"]),
        dict(services=["0000180a-0000-1000-8000-00805f9b34fb"]),
    ]

    for kwargs in all_kwargs:
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout

        print(f"find({', '.join(f'{k}={v}' for k, v in kwargs.items())})")
        async for device in find(**kwargs):
            print(repr(device))
        print()


def _test() -> None:
    # Enable debugging of the coroutines
    # noinspection SpellCheckingInspection
    os.environ["PYTHONASYNCIODEBUG"] = "1"
    asyncio.get_event_loop().set_debug(enabled=True)
    async_logger = logging.getLogger("asyncio")

    async_logger.setLevel(logging.DEBUG)
    logger.setLevel(logging.INFO)
    # Log to stdout
    async_logger.addHandler(logging.StreamHandler())
    logger.addHandler(logging.StreamHandler())

    asyncio.run(_test_find(), debug=True)


if __name__ == "__main__":
    _test()
