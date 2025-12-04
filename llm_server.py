from llmproxy import LLMProxy
import os
import sys
import socket
import requests
from bs4 import BeautifulSoup
from enum import Enum

from injection import *

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python llm_server.py <listen_port>")
        sys.exit(1)
    # make this nicer? print an error message with usage?

    listen_port = int(sys.argv[1])

    main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    main_sock.bind(('', listen_port))
    main_sock.listen(5)

    llm = LLMProxy()

    client_sock, client_addr = main_sock.accept()
    print("Proxy connected")


    def modify_header(header, new_len) -> str:
        content_line = ""
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_line = line
                break
        return header.replace(content_line, f"Content-Length: {new_len}")
        


        

    def process_response(header, body):
        print("in process_response\n")

        body = inject_html(body)
        print("html injected, modifying header")
        header = modify_header(header, len(body))

        print("header modified, finished processing response")
        return "".join([header, "\r\n\r\n", body])

    def inject_html(html) -> str:
        html += injection_1

        print("generating llm response\n")
        # get llm response and append to html
        response = llm.generate(
            model="us.anthropic.claude-3-haiku-20240307-v1:0",
            system="""
            Your task is to highlight and break up the text inside this web page into more readable chunks. 
            Focus on bolding main ideas and important details
            Do not change any of the actual words. 
            Do not split paragraphs or bold so much that it becomes meaningless.
            Exclude advertisements and unrelated content.
            Do not respond with anything other than the html.

            """,
            query=body,
            lastk=0
        )

        
        html += response['result']
        html += injection_2

        print(html)
        return html

        


    def parse_header(header) -> int:
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":")[1].strip())
                return content_length
                
            if line.lower().startswith("transfer-encoding:"):
                if line.split(":")[1].strip().lower() == "chunked":
                    return -1


    header = ""
    body = ""
    while True:
        buf = client_sock.recv(256)
        print("received some stuff from proxy\n")
        message = buf.decode('utf-8')
        header_chunk, CRLF, leftover = message.partition("\r\n\r\n")
        header += header_chunk
        if CRLF:
            print("found end of header")
            body += leftover
            print(body)
            
            length = parse_header(header)
            print(length)
            if (length == -1):
                # read chunked
                # split by /r/n, read first substring, translate hex to int, skip forward that many bytes in leftover, if longer than leftover read the rest, if shorter split on new chunk
                print("chunked encoding currently not handled")

            else: 
                # read content length
                bytes_left = length - len(leftover)
                print(len(leftover))
                while bytes_left > 0:
                    print(f"bytes left in body: {bytes_left}")
                    buf = client_sock.recv(bytes_left)
                    bytes_left -= len(buf)
                    body += buf.decode('utf-8')
                    # print(body)
                    # bytes_left = length - len(body)
                    
            message = process_response(header, body)

            print("processed response, sending result to proxy")

            print(message)
            client_sock.sendall(message.encode('utf-8'))
            print("sent result to proxy")


                    
            
                


    # process_response(message)
    # client_sock.sendall(message)
    
    

        # body = str()
        
        

        


        # """
        # will only have one client
        # //but has to serve responses for multiple profiles
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
        # """
