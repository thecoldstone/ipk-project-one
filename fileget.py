import socket
import re
import os
import argparse
from filegetparams import FileGetParams


class ServerError(Exception):
    """Server Exception cauesed by server error"""

    def __init__(self, message):
        super().__init__(message)


class FileGet(FileGetParams):
    """File Getter Class for fetching files from the server using UDP and TSP protocols"""

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
        """Create request body using FSP protocol

        Args:
            path (str): Path to the file

        Returns:
            str: Request body using FSP protocl
        """
        return f"GET {path} FSP/1.0\r\nHostname: {self.server}\r\nAgent: {self.agent}\r\n\r\n"

    def write_to_fail(self, path: str, socket: socket, respond: str):
        """Write a recieved data from the server into the file

        Args:
            path (str): Path to the file
            socket (socket): Already opened socket
            respond (str): Respond from the server
        """
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
        """Read a data from the file

        Args:
            path (str): Path to the file
            socket (socket): Already opened socket]
            respond (str): Respond from the server

        Returns:
            list: List of lines from the file
        """
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
        else:
            while True:
                res = socket.recv(1024).decode("ascii")
                res_content = res.split("\r\n")

                if len(res_content) > 0:
                    for index, line in enumerate(res_content):
                        if len(line) == 0:
                            continue
                        data.append(line)
                    break

                if not line:
                    break

                data.append(line)

        return data

    def create_path_to_file(self, path: str):
        """Create the path to the file

        Args:
            path (str): The absolute path to the file
        """
        if re.search("/", path):
            # Create new directory and change current pwd
            subpaths = path.split("/")
            cur_path = None
            for index, subpath in enumerate(subpaths):
                if index is len(subpaths) - 1:
                    break

                if cur_path is None:
                    cur_path = subpath
                else:
                    cur_path = f"{cur_path}/{subpath}"

                if os.path.exists(f"{os.getcwd()}/{cur_path}"):
                    continue
                else:
                    os.mkdir(f"{os.getcwd()}/{cur_path}")

    def fsp_get(self, host: str, port: int, path: str, return_content=False):
        """Fetch the file from the server

        Args:
            host (str): IPV4 protocol
            port (int): PORT
            path (str): Absolute path to the file
            return_content (bool, optional): Return the content of the read data. Defaults to False.

        Raises:
            ValueError: Once file has not been found
            ServerError: Internal error occured on the server side

        Returns:
            list: Return the list of the lines from the file if the return_content is set to true
        """
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
                raise ServerError(f"Internal error on the server side")

    def fsp_get_all(self, host: str, port: int):
        """Get all files from the server using fsp_get method

        Args:
            host (str): IPV4 protocol
            port (int): PORT
        """
        index_file_path = self.path[:-2] + "index"
        files = self.fsp_get(host, port, index_file_path, True)

        for file in files:
            self.fsp_get(host, port, file)

    def get_file(self):
        """Main function for fetching data from the server.

        Raises:
            SyntaxError:
            ValueError: [description]
            ServerError: [description]
        """
        message = f"whereis {self.server}"
        try:
            # Connect to server using UDP protocol
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.sendto(message.encode("utf-8"), self.address)
                res = udp.recvfrom(4096)
                res_state = res[0].decode("utf-8")

                if re.search("^ERR Syntax", res_state):
                    raise SyntaxError("Syntax error in the server name")
                elif re.search("^ERR Not Found", res_state):
                    raise ValueError(f"Server {self.server} has not been found")
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
        except Exception as e:
            print(f"[ERROR] {e}")


if __name__ == "__main__":

    def init_parser():
        """Argument Parser for FileGet

        Raises:
            ValueError: Incorrect IPV4 address
            ValueError: PORT is not an integer
            ValueError: Incorrect SURL
            ValueError: Incorrect SURL
            ValueError: Incorrect SURL
            ValueError: Incorrect SURL

        Returns:
            dictionary: Return the dictionary with all needed arguments for FileGet initialization
        """
        parser = argparse.ArgumentParser(
            description="Fetching files from the server using UDP/TCP sockets."
        )
        parser.add_argument("-n", nargs=1, required=True, help="The server name")
        parser.add_argument(
            "-f",
            nargs=1,
            required=True,
            help="SURL to the file on the server.\n\tExample: fsp://foo.bar/file.txt",
        )

        args = parser.parse_args()

        address = args.n[0].split(":")

        if len(address) != 2:
            raise ValueError("Incorrect IPV4 address")

        try:
            address[1] = int(address[1])
        except:
            raise ValueError("PORT is not an integer")

        surl = args.f[0]

        if re.search("^fsp:\/\/\w+", surl) is None:
            raise ValueError("Incorrect SURL")

        res = re.match(r"(^fsp:\/\/)([\w][^\/]+)(?:(\/\*)|(\/.*))", surl)
        if res is None:
            raise ValueError("Incorrect SURL")

        if res.group(0) != surl:
            raise ValueError("Incorrect SURL")

        path = None
        if res.group(3):
            path = res.group(3)

        if res.group(4):
            if res.group(4) == "/":
                raise ValueError("Incorrect SURL")
            path = res.group(4)

        return {
            "ip": address[0],
            "port": address[1],
            "protocol": res.group(1)[:3],
            "server": res.group(2),
            "path": path[1:],
        }

    try:
        args = init_parser()
    except Exception as e:
        print(f"[ERROR] {e}")
        exit(1)

    AGENT = "xzhuko01"

    """Test with with default arguments"""
    # IP = "127.0.0.1"
    # PORT = 3333
    # PROTOCOL = "fsp"
    # SERVER = "muj.server.number.ones"
    # PATH = "folder/folder3"

    """Test with with input arguments"""
    IP = args["ip"]
    PORT = args["port"]
    PROTOCOL = args["protocol"]
    SERVER = args["server"]
    PATH = args["path"]

    client = FileGet(
        ip=IP, port=PORT, agent=AGENT, protocol=PROTOCOL, server=SERVER, path=PATH
    )
    client.get_file()
