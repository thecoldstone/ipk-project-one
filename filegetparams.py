class FileGetParams:
    """FileGetParams class for storing params such as protocol, server, and path. Created in case of further extension"""

    def __init__(self, protocol: str, server: str, path: str):
        self.protocol = protocol
        self.server = server
        self.path = path

    @property
    def protocol(self):
        return self.__protocol

    @protocol.setter
    def protocol(self, protocol):
        if protocol == "fsp":
            self.__protocol = protocol
        else:
            raise ValueError(f"The protocol {protocol} is not supported")

    @property
    def server(self):
        return self.__server

    @server.setter
    def server(self, server):
        if server == "":
            raise ValueError(f"The server cannot be empty")
        else:
            self.__server = server

    @property
    def path(self):
        return self.__path

    @path.setter
    def path(self, path):
        if path == "":
            raise ValueError(f"The path cannot be empty")
        else:
            self.__path = path

    @property
    def surl(self):
        return f"{self.protocol}://{self.server}/{self.path}"