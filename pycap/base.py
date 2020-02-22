class DataObject:

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

    def describe(self) -> dict:
        raise NotImplementedError()


BYTE_ORDER = 'big'
