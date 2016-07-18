
# coding: utf-8

# In[308]:

# Imported Libraries and Modules
import os
import time
import json
import boto3
import base64
import string
import hashlib
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from Crypto import Random
#from string import Formatter


# In[309]:

# Retrieves name of S3 Bucket

def get_bucket_name(data):
    bucket_name = data["Records"][0]["s3"]["bucket"]["name"]
    return bucket_name


# In[310]:

# Retrieves file name from object

def get_file_name(data):
    file_name = data["Records"][0]["s3"]["object"]["key"]
    return file_name


# In[311]:

# Creates folder with today's date if one does not already exist
# and moves to it

def create_directory ():
    dir_name = time.strftime("%m-%d-%Y")
    try: os.makedirs(r'C:\Users\Harrison\Documents\%s' % dir_name)
    except: pass
    os.chdir(r'C:\Users\Harrison\Documents\%s' % dir_name)


# In[312]:

# Downloads file from S3 Bucket

def file_downloader(file_name, bucket):
    try: 
        s3.Bucket(bucket).download_file(file_name, "Downloaded- " + file_name)
    except:
        print("File failed to download")
    print("Downloading file: " + file_name)


# In[313]:

# Returns true if MD5s match

def compare_md5(md1, md2):
    if md1 == md2:
        return True
    return False


# In[314]:

# Obtains the MD5 hash from the S3 Object

def get_md5(file_name, bucket_name):
    md5sum = boto3.client('s3').head_object(Bucket = bucket_name, Key = file_name)['ETag'][1:-1]
    return md5sum


# In[315]:

# Calculates the hash of the downloaded file

def calculat_md5(file_name):
    md5 = hashlib.md5(open(file_name,'rb').read()).hexdigest()
    return md5


# In[316]:

# Removes file from S3 Bucket

def delete_file(file_name, bucket_name):
    try:
        s3.Bucket(bucket_name).delete_objects( Delete={'Objects':[{ 'Key': file_name}]})
        print("Deleting " + file_name + " from Bucket")
    except:
        print("Failed to delete file from Bucket")


# In[317]:

# Removes message from SQS Queue

def delete_message(one_message):
    try:
        one_message.delete()
        print("Message deleted from queue")
    except:
        print("Message deletion failed")


# In[318]:

# Retrieves key from object in S3 Bucket

def get_key(file_name, bucket_name):
    obj = s3.Bucket(bucket_name).Object(file_name)
    data = obj.get()
    encrypted_key = data["ContentType"]
    return encrypted_key


# In[319]:

# Strips key of excess characters from string/byte conversions

def strip_key(encrypted_key):
    encrypted_key = encrypted_key.strip('b')
    encrypted_key = encrypted_key.strip("'")
    return encrypted_key


# In[320]:

# This function decrypts the encrypted AES key using RSA

def key_decryption(bytes_key):
    private_rsa_key = RSA.importKey(open('c:/cygwin64/certs/fred.pri.key').read())
    dsize = SHA.digest_size
    sentinel = Random.new().read(AES.block_size)
    cipher = PKCS1_v1_5.new(private_rsa_key)
    raw_aes_key = cipher.decrypt(bytes_key, sentinel)
    return raw_aes_key


# In[321]:

def extract_key(raw_aes_key):
    raw_aes_key = str(raw_aes_key)
    raw_aes_key = raw_aes_key[2:34]
    return raw_aes_key


# In[322]:

# Decodes string from base 64 to bytes

def decode_64(string):
    new = base64.b64decode(string)
    return new


# In[323]:

# Creates AES cipher

def create_aes_cipher(raw_aes_key):
    iv = Random.new().read(16)
    aes_cipher = AES.new(raw_aes_key, AES.MODE_CFB, iv)
    return aes_cipher


# In[324]:

# Decrypts file using aes cipher

def file_decryption(encrypted_file_handle, aes_cipher):
    decrypted_text = aes_cipher.decrypt(encrypted_file_handle)
    return decrypted_text


# In[325]:

def strip_text(decrypted_key):
    text_length = len(decrypted_key)
    decrypted_text = decrypted_key[16:text_length]
    return decrypted_text


# In[326]:

# Initial values and AWS resources set

message_queue_status = 1
sqs=boto3.resource('sqs')
s3=boto3.resource('s3')
artifacts=sqs.Queue('https://sqs.us-west-2.amazonaws.com/114007456961/artifacts')
m = artifacts.receive_messages(MaxNumberOfMessages=1,WaitTimeSeconds=5,MessageAttributeNames=['*'],AttributeNames=['All'])


# Try block will fail if no messages are in the queue
try:
    one_message = m[0]
except:
    print("Error")
    message_queue_status = 0
    
# Only executes if there is a message in the queue    

if message_queue_status == 1:  
    
    create_directory()
    
# This section loads the message and retrieves the file and bucket name
# of the upload that triggered the message

    data = json.loads(one_message.body)
    bucket_name = get_bucket_name(data)
    file_name = get_file_name(data)
    file_downloader(file_name, bucket_name)
  
 # Calculates the MD5 hash of the file after it has been doanloaded
# and compares it to the hash of the object in S3
    try:
        md5_1 = get_md5(file_name, bucket_name)
        md5_2 = calculat_md5("Downloaded- " + file_name)
    except:
        print("MD5 retrieval/calculation failed")
        
    if compare_md5(md5_1, md5_2) == False:
        raise Exception("MD5 values did not match")
    else:
        print("MD5 values match")
        print("MD5 : " + md5_1)
# Obtains key from object metadata, strips b'' from key and 
# converts back to a bytes object
        encrypted_key = get_key(file_name, bucket_name) 
        delete_file(file_name, bucket_name)  
        delete_message(one_message)    

# Removes excess characters from type conversion and decodes
    encrypted_key = strip_key(encrypted_key)
    bytes_key = base64.b64decode(encrypted_key)    

# Decrypts AES key with RSA and removes excess characters   
    raw_aes_key = key_decryption(bytes_key)
    raw_aes_key = extract_key(raw_aes_key)

# Opens files, one for encrypted file and one for decrypted
    encrypted_file_handle = open('Downloaded- %s' % file_name, "rb").read() 
    decrypted_file_handle = open('Decrypted_%s' % file_name, 'wb')

# Creates AES cipher and decypts file with AES
    aes_cipher = create_aes_cipher(raw_aes_key)
    decrypted_text = file_decryption(encrypted_file_handle, aes_cipher)
    stripped_text = strip_text(decrypted_text)
    decrypted_file_handle.write(stripped_text)
    decrypted_file_handle.close()
    
else:
    print("Message Queue empty")


# In[ ]:



