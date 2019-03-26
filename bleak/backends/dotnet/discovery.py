# -*- coding: utf-8 -*-
"""
Perform Bluetooth LE Scan.

Created on 2017-12-05 by hbldh <henrik.blidh@nedomkull.com>

"""
import datetime
import enum
import pathlib
import logging
import asyncio
# noinspection PyCompatibility
from dataclasses import dataclass
from typing import List, Optional, Union, Pattern, Iterable
from asyncio.events import AbstractEventLoop

from bleak.backends.device import BLEDevice

# Import of Bleak CLR->UWP Bridge. It is not needed here, but it enables loading of Windows.Devices
# noinspection PyUnresolvedReferences
from BleakBridge import Bridge

# noinspection PyUnresolvedReferences,PyPackageRequirements
from System import Array, Byte
# noinspection PyUnresolvedReferences,PyPackageRequirements
from Windows.Devices import Enumeration

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
_here = pathlib.Path(__file__).parent


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


async def discover(
    timeout: float = 5.0, loop: AbstractEventLoop = None, **kwargs
) -> List[BLEDevice]:
    """Perform a Bluetooth LE Scan.

    Args:
        timeout (float): Time to scan for.
        loop (Event Loop): The event loop to use.

    Keyword Args:
        string_output (bool): If set to false, ``discover`` returns .NET
            device objects instead.

    Returns:
        List of strings or objects found.

    """
    loop = loop if loop else asyncio.get_event_loop()

    requested_properties = Array[str](
        [
            "System.Devices.Aep.DeviceAddress",
            "System.Devices.Aep.IsConnected",
            "System.Devices.Aep.Bluetooth.Le.IsConnectable",
        ]
    )
    aqs_all_bluetooth_le_devices = '(System.Devices.Aep.ProtocolId:="' '{bb7bb05e-5972-42b5-94fc-76eaa7084d49}")'
    watcher = Enumeration.DeviceInformation.CreateWatcher(
        aqs_all_bluetooth_le_devices,
        requested_properties,
        Enumeration.DeviceInformationKind.AssociationEndpoint,
    )

    devices = {}

    def _format_device_info(d):
        try:
            return "{0}: {1}".format(
                d.Id.split("-")[-1], d.Name if d.Name else "Unknown"
            )
        except Exception:
            return d.Id

    def DeviceWatcher_Added(sender, dinfo):
        if sender == watcher:

            logger.debug("Added {0}.".format(_format_device_info(dinfo)))
            if dinfo.Id not in devices:
                devices[dinfo.Id] = dinfo

    def DeviceWatcher_Updated(sender, dinfo_update):
        if sender == watcher:
            if dinfo_update.Id in devices:
                logger.debug(
                    "Updated {0}.".format(_format_device_info(devices[dinfo_update.Id]))
                )
                devices[dinfo_update.Id].Update(dinfo_update)

    def DeviceWatcher_Removed(sender, dinfo_update):
        if sender == watcher:
            logger.debug(
                "Removed {0}.".format(_format_device_info(devices[dinfo_update.Id]))
            )
            if dinfo_update.Id in devices:
                devices.pop(dinfo_update.Id)

    def DeviceWatcher_EnumCompleted(sender, obj):
        if sender == watcher:
            logger.debug(
                "{0} devices found. Enumeration completed. Watching for updates...".format(
                    len(devices)
                )
            )

    def DeviceWatcher_Stopped(sender, obj):
        if sender == watcher:
            logger.debug(
                "{0} devices found. Watcher status: {1}.".format(
                    len(devices), watcher.Status
                )
            )

    watcher.Added += DeviceWatcher_Added
    watcher.Updated += DeviceWatcher_Updated
    watcher.Removed += DeviceWatcher_Removed
    watcher.EnumerationCompleted += DeviceWatcher_EnumCompleted
    watcher.Stopped += DeviceWatcher_Stopped

    # Watcher works outside of the Python process.
    watcher.Start()
    await asyncio.sleep(timeout, loop=loop)
    watcher.Stop()

    try:
        watcher.Added -= DeviceWatcher_Added
        watcher.Updated -= DeviceWatcher_Updated
        watcher.Removed -= DeviceWatcher_Removed
        watcher.EnumerationCompleted -= DeviceWatcher_EnumCompleted
        watcher.Stopped -= DeviceWatcher_Stopped
    except Exception as e:
        logger.debug("Could not remove event handlers: {0}...".format(e))

    found = []
    for d in devices.values():
        properties = {p.Key: p.Value for p in d.Properties}
        found.append(
            BLEDevice(properties["System.Devices.Aep.DeviceAddress"], d.Name, d)
        )

    return found


async def find(mac: Union[None, str, Pattern] = None,
               name: Union[None, str, Pattern] = None,
               services: Optional[Iterable[Union[str, Pattern]]] = None,
               timeout: float = 5.0,
               loop: AbstractEventLoop = None) -> None:  # AsyncIterable[BLEDevice]:
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
                     device must provide all of them. 16-bit UUIDs are
                     considered SIG services.
    :param timeout: Maximum time to scan for (seconds). If negative number then
                    the scan will stop as soon as the first device is found.

    :param loop: The event loop to use.

    :returns: Devices as soon as they are found and updated.
    """
    loop = loop if loop else asyncio.get_event_loop()

    watcher = BluetoothLEAdvertisementWatcher()
    # Task is used for scan timeout to enable premature scan stop.
    sleep_task = asyncio.Future()

    def advertisement_watcher__received(sender: BluetoothLEAdvertisementWatcher,
                                        args: BluetoothLEAdvertisementReceivedEventArgs):
        # print(f"advertisement_watcher__received({sender}, {args})")
        try:
            p_obj = AdvertisementReceivedEventArgs(args)
            logger.debug(str(p_obj))
        except Exception as e:
            logger.error(str(e))

    def advertisement_watcher__stopped(sender: BluetoothLEAdvertisementWatcher,
                                       args: BluetoothLEAdvertisementWatcherStoppedEventArgs):
        logger.debug("advertisement_watcher__stopped({}, {})".format(sender, args))

    watcher.Received += advertisement_watcher__received
    watcher.Stopped += advertisement_watcher__stopped
    watcher.ScanningMode = BluetoothLEScanningMode.Active

    # Watcher works outside of the Python process.
    watcher.Start()
    try:
        await asyncio.wait_for(sleep_task, timeout=timeout, loop=loop)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass
    watcher.Stop()


def _test_find() -> None:
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    loop = asyncio.get_event_loop()

    loop.run_until_complete(find(timeout=10))


if __name__ == "__main__":
    _test_find()
