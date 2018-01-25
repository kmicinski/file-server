#!/usr/bin/python

# Allow using the `socket` library
import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 5000))

def crash_server():
    """Crashes the server using a stack-smashing attack"""
    return

def hello_world():
    """Forces the server to print 'Hello, world!'"""
    return

def inject_execute_shellcode():
    """Crashes the server using a stack-smashing attack"""
    return

