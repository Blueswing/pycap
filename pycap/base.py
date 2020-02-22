from typing import Optional, Tuple


class Header:

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

    @property
    def upper_layer_protocol(self) -> Optional[str]:
        return None

    def describe(self) -> dict:
        raise NotImplementedError()


class Protocol:

    def unpack_data(self, data: bytes) -> Tuple[Header, bytes]:
        raise NotImplementedError()


class NotSupportedError(Exception):
    pass
