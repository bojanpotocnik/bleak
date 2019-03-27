# -*- coding: utf-8 -*-
"""
Wrapper class for Bluetooth LE servers returned from calling
:py:meth:`bleak.discover`.

Created on 2018-04-23 by hbldh <henrik.blidh@nedomkull.com>

"""
from typing import TYPE_CHECKING, Optional, Union, Any

if TYPE_CHECKING:  # Do not import objects used only for Lint type checking in runtime.
    # noinspection PyUnresolvedReferences
    from .dotnet.discovery import Enumeration
    from .dotnet.search import AdvertisementReceivedEventArgs


class BLEDevice(object):
    """A simple wrapper class representing a BLE server detected during
    a `discover` call.

    - When using Windows backend, `details` attribute is a
      `Windows.Devices.Enumeration.DeviceInformation` object.
    - When using Linux backend, `details` attribute is a
      string path to the DBus device object.
    - When using macOS backend, `details` attribute will be
      something else.

    """

    def __init__(self, address: str, name: Optional[str],
                 details: Union['Enumeration.DeviceInformation', 'AdvertisementReceivedEventArgs', str, Any] = None):
        self.address = address
        self.name = name  # name or "Unknown"
        self.details = details

    @property
    def _name_string(self) -> str:
        """
        Return name, distinguishing between name None ('None'),
        empty name ('') and no name at all (None).
        """
        return "None" if (self.name is None) else "'{}'".format(self.name)

    def __str__(self) -> str:
        return "{0}({1}, {2})".format(type(self).__name__, self.address, self._name_string)

    def __repr__(self) -> str:
        return "{0}({1}, {2}, {3}({4}))".format(type(self).__name__, self.address, self._name_string,
                                                type(self.details), self.details)

    @property
    def id(self) -> str:
        try:
            # In .NET the Enumeration.DeviceInformation has an Id property.
            # However if not using .NET backend, this class is not available/imported.
            if isinstance(self.details, Enumeration.DeviceInformation):
                return self.details.Id
            if isinstance(self.details, AdvertisementReceivedEventArgs):
                return self.details.bluetooth_address
        except NameError:  # name 'Enumeration' is not defined
            pass
        # On Linux, the DBus path to the device is unique for each device.
        # TODO: What are the details on MacOS? Probably similar to Linux.
        return self.details
