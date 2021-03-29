import socket
import re
import os
from filegetparams import FileGetParams


class ServerError(Exception):
    def __init__(self, message):
        super().__init__(message)


class FileGet(FileGetParams):
    def __init__(
        self, ip: str, port: int, server: str, agent: str, path="", protocol="fsp"
    ):
        self.ip = ip
        self.port = port
        self.agent = agent
        FileGetParams.__init__(self, protocol, server, path)

    @property
    def ip(self):
        return self.__ip

    @ip.setter
    def ip(self, ip):
        if ip != "":
            self.__ip = ip
        else:
            raise ValueError("IP Address is missing")

    @property
    def port(self):
        return self.__port

    @port.setter
    def port(self, port):
        self.__port = port

    @property
    def address(self):
        return self.ip, self.port

    def get_body_request(self, path):
        return f"GET {path} FSP/1.0\r\nHostname: {self.server}\r\nAgent: {self.agent}\r\n\r\n"

    def write_to_fail(self, path: str, socket: socket, respond: str):
        with open(path, "wb") as f:
            res_content = respond.split("\r\n")
            # Check if the respond body has got already the requested content
            if len(res_content[3]) > 0:
                for index, string in enumerate(res_content):
                    # Skip Version Status and Headers in Respond body
                    if index < 3:
                        continue

                    if index is not len(res_content) - 1:
                        string = f"{string}\n"

                    f.write(string.encode("ascii"))

                f.close()
                return

            while True:
                data = socket.recv(1024)
                if not data:
                    break
                f.write(data)

    def read_from_file(self, path: str, socket: socket, respond: str):
        filename = os.path.basename(path)
        data = []
        res_content = respond.split("\r\n")
        # Check if the respond body has got already the requested content
        if len(res_content[3]) > 0:
            for index, line in enumerate(res_content):
                # Skip Version Status and Headers in Respond body
                if index < 3:
                    continue
                if len(line) == 0:
                    continue
                data.append(line)
                # if index is not len(res_content) - 1:
                #     string = f"{string}\n"

                #     f.write(string.encode('ascii'))

                # f.close()
        else:
            while True:
                line = socket.recv(1024)
                if not line:
                    break
                data.append(line)

        return data

    def create_path_to_file(self, path: str):
        if re.search("/", path):
            # Create new directory and change current pwd
            subpaths = path.split("/")
            cur_path = None
            for index, subpath in enumerate(subpaths):
                if cur_path is None:
                    cur_path = subpath
                else:
                    cur_path = f"{cur_path}/{subpath}"

                if index is len(subpaths) - 1:
                    break

                if os.path.exists(f"{os.getcwd()}/{cur_path}"):
                    continue
                else:
                    os.mkdir(f"{os.getcwd()}/{cur_path}")

    def fsp_get(self, host: str, port: int, path: str, return_content=False):

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tsp:
            tsp.settimeout(30)
            tsp.connect((host, port))
            tsp.sendall(self.get_body_request(path).encode("ascii"))

            res = tsp.recv(1024).decode("utf-8")
            res_state = res[7:].split("\r\n")[0]

            if re.search("Success", res_state):
                self.create_path_to_file(path)
                if return_content is False:
                    self.write_to_fail(path, tsp, res)
                else:
                    return self.read_from_file(path, tsp, res)

            elif re.search("Not Found", res_state):
                raise ValueError(f"The file {path} has not been found")
            else:
                raise ServerError(f"Internal error on server side")

    def fsp_get_all(self, host: str, port: int):

        index_file_path = self.path[:-1] + "index"
        files = self.fsp_get(host, port, index_file_path, True)

        for file in files:
            self.fsp_get(host, port, file)

    def get_file(self):
        # TODO add try/except
        message = f"whereis {self.server}"

        # Connect to server
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(message.encode("utf-8"), self.address)
            res = udp.recvfrom(4096)
            res_state = res[0].decode("utf-8")

            if re.search("^ERR Syntax", res_state):
                raise SyntaxError("Syntax error in the server name")
            elif re.search("^ERR Not Found", res_state):
                raise ValueError(f"{server} not found")
            elif re.search("^OK", res_state):
                # Connect to the subserver
                # Do TCP connection via surl
                host = res_state[3 : res_state.find(":")]
                port = int(res_state[res_state.find(":") + 1 :])

                if os.path.basename(self.path) == "*":
                    self.fsp_get_all(host, port)
                else:
                    self.fsp_get(host, port, self.path)
            else:
                raise ServerError(f"Internal error on server side")


if __name__ == "__main__":
    IP = "127.0.0.1"
    PORT = 3333
    AGENT = "xzhuko01"
    PROTOCOL = "fsp"
    SERVER = "muj.server.number.one"
    PATH = "*"

    client = FileGet(
        ip=IP, port=PORT, agent=AGENT, protocol=PROTOCOL, server=SERVER, path=PATH
    )
    client.get_file()
