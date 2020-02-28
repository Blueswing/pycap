from typing import Optional, Tuple


class DataObject:

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

    def describe(self) -> dict:
        raise NotImplementedError()


class Header(DataObject):

    @property
    def upper_layer_protocol(self) -> Optional[str]:
        return None


class Protocol:

    def unpack_data(self, data: bytes) -> Tuple[Header, bytes]:
        raise NotImplementedError()


class NotSupportedError(Exception):
    pass
