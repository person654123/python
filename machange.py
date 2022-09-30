#!/bin/python3

from subprocess import call
from time import sleep as s

from random import randint as rad

lst = []

for i in range(6):
    lst.append(str(rad(0, 99)).zfill(2))

while not (int(lst[0]) % 2 == 0):  # This step insures the mac address starts with an even number
    lst.remove(lst[0])
    lst.insert(0, str(rad(0, 99)).zfill(2))

mac = ":".join(lst)

call("ifconfig", shell=True)

s(0.4)

print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

s(1)

call("ifconfig eth0 down " + mac, shell=True)

s(1)

call("ifconfig eth0 hw ether " + mac, shell=True)

s(1)

call("ifconfig eth0 up", shell=True)

s(1)

call("ifconfig", shell=True)

print("The new mac address is " + mac)
