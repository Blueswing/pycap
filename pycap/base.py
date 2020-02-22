from typing import Optional


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


