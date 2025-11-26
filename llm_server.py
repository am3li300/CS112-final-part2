from llmproxy import LLMProxy
import os
import sys
import socket

"""
Usage: python llm_server.py <listen_port> <proxy_ip> <proxy_port>
"""
if __name__ == '__main__':
    print("Hello World")
    assert sys.argc == 4
    # make this nicer? print an error message with usage?

    listen_port = sys.argv[1]
    proxy_ip = sys.argv[2]
    proxy_port = sys.argv[3]
    # do some kind of type checking?

    main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    main_sock.bind(socket.INADDR_ANY, listen_port)
    main_sock.listen(5)

    llm = LLMProxy()

    while True:
        """
        possibly also use select unfortunately
        maintain a client list

        read/write clients
            take in webpage/hello message w profile info?, modify it, write it back

        accept new clients
        """
    


    # listen on a port