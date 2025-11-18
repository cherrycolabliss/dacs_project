from client import load_private_key

'''
This file is for testing the PIN. 

Edit: Probably not needed now since I've added the ability to
manully input the PIN in the client.py file, but i'll keep this here just in case.
'''

filename = "alice_private_key.json"
pin = input("PIN: ")

try:
    key = load_private_key(filename, pin)
    print("Decryption SUCCESS")
except Exception as e:
    print("ERROR:", e)
