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

    # client_sock = socket.accept

    while True:
        # will only have one client
        # but has to serve responses for multiple profiles
        # in proxy we can inject http header to have profile info and client id, 
        # maybe we can also inject with a feedback line if client is like too many words bolded or smthn like that

        # socket.read
        # figure out python way to parse http message this must be way easier surely
        # note that everything you read will be 200 OK webpages

        # if complete message, parse out profile info
        # feed body to llm using profile parameters
        # if feedback header, modify prompt/make it so all future stuff for this profile has this change
        #     /if we are doing predetermined options for feedback have a majority win system
        #     where the majority determines the prompt modification
        # get back augmented webpage

        # socket.write to client

        # i have no idea how we are going to get interactive info from client in the proxy though

        
        # in the proxy, when you accept new clients, immediately send back some kind of loading page
