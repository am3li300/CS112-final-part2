from llmproxy import LLMProxy
import os
import sys
import socket
import requests
from bs4 import BeautifulSoup
from enum import Enum
import gzip
import brotli

from injection import *

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python llm_server.py <listen_port>")
        sys.exit(1)

    listen_port = int(sys.argv[1])

    main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    main_sock.bind(('', listen_port))
    main_sock.listen(5)

    llm = LLMProxy()

    client_sock, client_addr = main_sock.accept()
    print("Proxy connected")

    def inject_html(body_str) -> str:
        html = body_str + injection_1

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
            query= body_str,
            lastk=0
        )

        
        html += response['result']
        html += injection_2

        return html
    

    def decompress(header_str, body) -> str:
        # 1 for gzip, 2 for br
        encoding_type = ""
        for line in header_str.split("\r\n"):
            if line.lower().startswith("content-encoding:"):
                encoding_type = line.split(":")[1].strip()
                break

        decompressed = body
        if encoding_type == "gzip":
            decompressed = gzip.decompress(body)
        elif encoding_type == "br":
            decompressed = brotli.decompress(body)

        return decompressed.decode('utf-8')
    

    def recompress(header_str, body_str):
        encoding_type = ""
        for line in header_str.split("\r\n"):
            if line.lower().startswith("content-encoding:"):
                encoding_type = line.split(":")[1].strip()
                break

        compressed = body_str.encode('utf-8')
        if encoding_type == "gzip":
            return gzip.compress(compressed)
        elif encoding_type == "br":
            return brotli.compress(compressed)
        else: return compressed
    

    def modify_header(header, new_len) -> str:
        content_line = ""
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_line = line
                break
        return header.replace(content_line, f"Content-Length: {new_len}")


    def process_response(header_str, body) -> str:
        print("in process_response\n")

        body_str = decompress(header_str, body)
        print("DECOMPRESSED BODY")
        print(body_str)
        print()

        body_str = inject_html(body_str)
        print("MODIFIED BODY")
        print(body_str)
        print()

        new_body = recompress(header_str, body_str)
        header_str = modify_header(header_str, len(new_body))
        print("UPDATED HEADER")
        print(header_str)
        print()

        return b"".join([header_str.encode('utf-8'), b"\r\n\r\n", new_body])

        
    def parse_header(header) -> int:
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":")[1].strip())
                return content_length
                
            if line.lower().startswith("transfer-encoding:"):
                if line.split(":")[1].strip().lower() == "chunked":
                    return -1


    header = b''
    while True:
        buf = client_sock.recv(256)
        # print("received some stuff from proxy\n")
        header_chunk, CRLF, leftover = buf.partition(b"\r\n\r\n")
        header += header_chunk
        if CRLF:
            body = leftover
            
            header_str = header.decode('utf-8')
            print("HEADER")
            print(header_str)
            print()

            length = parse_header(header_str)
            print(length)
            if (length == -1):
                # read chunked
                # split by /r/n, read first substring, translate hex to int, skip forward that many bytes in leftover, if longer than leftover read the rest, if shorter split on new chunk
                print("chunked encoding currently not handled")

            else: 
                # read content length
                bytes_left = length - len(leftover)
                # print(len(leftover))
                while bytes_left > 0:
                    buf = client_sock.recv(bytes_left)
                    bytes_left -= len(buf)
                    body += buf
            
            message = process_response(header_str, body) # message will be compressed in bytes with content length updated

            print("processed response, sending result to proxy")

            # print(message)
            client_sock.sendall(message)
            print("sent result to proxy")
            header = b''


                    
            
                


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
