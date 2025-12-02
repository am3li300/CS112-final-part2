from llmproxy import LLMProxy
import os
import sys
import socket
import requests
from bs4 import BeautifulSoup

"""
Usage: python llm_server.py <listen_port>
"""
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python llm_server.py <listen_port>")
        sys.exit(1)
    # make this nicer? print an error message with usage?

    # listen_port = int(sys.argv[1])

    # main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # main_sock.bind(('', listen_port))
    # main_sock.listen(5)

    # llm = LLMProxy()

    # client_sock, client_addr = main_sock.accept()



    resp = requests.get("https://example.com")
    html = resp.text
    headers = resp.headers
    
    soup = BeautifulSoup(html, "html.parser")

    title_tag = soup.title
    print(f"Title: {title_tag.string}")

    # while True:
        """
        1) do a read, get some response message
        
        2) parse the response headers - make sure its actually the html file

        3) get the html body 

        4) feed html into llm

        5) return to proxy

        PROXY SIDE - need to implement usage of LLM server
            1) every time a server writes to client, send it through the LLM before 
            forwarding


        """
        # buf = client_sock.recv(8192)

        # if len(buf) > 0:
        #     print(buf.decode('utf-8'))

        # header, body = raw.split(b"\r\n\r\n", 1)

        # html = body.decode("utf-8", errors="ignore")
        # headers = header_bytes.decode(errors="ignore")




        # """
        # parse http message into some structure
        # feed body to llm
        # replace body in structure
        # """

        # body = str()
        
        # response = client.generate(
        #     model="us.anthropic.claude-3-haiku-20240307-v1:0",
        #     system="Break up this html into more readable chunks, bolding the most important words. Do not change the actual words.",
        #     query=body,
        #     lastk=0
        # )

        


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
