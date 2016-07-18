
# coding: utf-8

# In[353]:

#Creates and Initializes Offset Value in a separate file
#Only need to run this once

def offset_initializer():
    offset_file_handle = open('Offset_Counter', 'w')
    offset_file_handle.write('1')
    offset_file_handle.close()


# In[354]:

# Imported Libraries and Modules

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto import Random
import random
import os
import string
import boto3
import base64


# In[355]:

#Reads offset file and return the value that it finds

def read_offset_value():
    offset_file_handle = open('Offset_Counter', 'r')
    counter_value = int(offset_file_handle.read())
    offset_file_handle.close()
    return counter_value


# In[356]:

#Updates the offset counter file once the new files have been created

def update_offset_value(new_offset_value):
    offset_file_handle = open('Offset_Counter', 'w')
    offset_file_handle.write(str(new_offset_value))
    offset_file_handle.close()


# In[357]:

#Increments the offset value by one

def increment_offset_value(current_offset_value):
    offset_file_handle = open('Offset_Counter', 'w')
    offset_file_handle.write(str(current_offset_value + 1))
    offset_file_handle.close()


# In[358]:

# Writes random data (33KB) to a file

def write_data_to_file(test_file_handle):
    iterations = 0
    while (iterations<500):
        test_file_handle.write(str(os.urandom(22)))
        iterations += 1


# In[359]:

# Function that creates files based on user input with unique names
# according to the offset value

def create_file(current_offset):
    test_file_handle = open('File_No_'+ "%06d"%current_offset,'w') 
    return test_file_handle


# In[360]:

# This function creates and returns a random string of characters for the AES key

def generate_random_key():
    raw_aes_key = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
    return raw_aes_key


# In[361]:

# Converts the AES key to bytes

def string_to_bytes(raw_aes_key):
    bytes_aes_key = str.encode(raw_aes_key)
    return bytes_aes_key


# In[362]:

# Imports key from certificate

def get_public_rsa_key():
    public_RSA_key = RSA.importKey(open('c:/cygwin64/certs/fred.pem').read())
    return public_RSA_key


# In[363]:

# Uses RSA to encrypt aes key

def encrypt_with_rsa(public_RSA_key, bytes_aes_key):
    rsa_cipher = PKCS1_v1_5.new(public_RSA_key)
    aes_key_encrypted_by_rsa = rsa_cipher.encrypt(bytes_aes_key)
    return aes_key_encrypted_by_rsa


# In[364]:

# Generates Initialization vector and AES cipher
def create_aes_cipher(raw_aes_key):
    iv = Random.new().read(AES.block_size)
    aes_cipher = AES.new(raw_aes_key, AES.MODE_CFB, iv)
    return aes_cipher, iv


# In[365]:

# Encrypts file using aes cipher

def aes_file_encryption(original_file_handle, new_file_handle, aes_cipher, iv): 
    new_file_handle.write(iv + aes_cipher.encrypt(original_file_handle))


# In[366]:

# Changes encrypted aes key to base 64

def base_64(encrypted_aes_key):
    new = base64.b64encode(encrypted_aes_key)
    return new


# In[367]:

# Uploads the array of files passed to it from main

def file_uploader(encrypted_file_handle, offset, new_key):
    s3 = boto3.resource('s3')
    s3.Bucket('artifact-attachment').upload_file('Encrypted_No_'+ "%06d"%offset,'File_No_'+ "%06d"%offset, ExtraArgs = {"ContentType" : new_key})
    print('\nFile_No_'+ "%06d"%offset + " uploaded to Bucket")


# In[368]:

# Main function- Reads offset file, takes input from user for number of files
# to be created. Creates the files and then updates the offset file counter

# If y is entered, counter will start over at 00001
offset_command = input("Enter 'y' or 'Y' to reset offset to Zero -> ")
if offset_command == 'y' or 'Y':
    offset_initializer()

# Creates new file with offset in the filename and writes random data to the file
current_offset_value = read_offset_value()
new_file_object = create_file(current_offset_value)
write_data_to_file(new_file_object)

# Creates an AES key to encrypt file and encrypts that key with RsA
raw_aes_key = generate_random_key()
bytes_aes_key = string_to_bytes(raw_aes_key)
public_rsa_key = get_public_rsa_key()
aes_key_encrypted_by_rsa = encrypt_with_rsa(public_rsa_key, bytes_aes_key)
original_file_handle = open(r'C:\Users\Harrison\Documents\%s' % 'File_No_'+ "%06d"%current_offset_value, "rb").read()  
aes_cipher, iv = create_aes_cipher(raw_aes_key)    

# Writes encrypted data to new file
encrypted_file_handle = open(r'C:\Users\Harrison\Documents\Encrypted_No_000001', 'wb')
aes_file_encryption(original_file_handle, encrypted_file_handle, aes_cipher, iv)
encrypted_file_handle.close()

# Converts encrypted key to string format and uploads file
new_key = str(base_64(aes_key_encrypted_by_rsa))
file_uploader(encrypted_file_handle,current_offset_value, new_key)

increment_offset_value(current_offset_value)


# In[ ]:



