import os
import boto3
import time
import random
import string
from datetime import datetime
import uuid

# notes:
'''this is a tool used for functionally testing that s3 document utility has been optimised
set bucketname to s3 bucket
you need to configure credentials using the aws cli tool first
https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html

make sure you dont put over 2000 files or 5GB a month into s3 using this tool or you will be charged :)

requires boto3, can get it with pip install boto3

'''
BUCKETNAME = 'documentutilitybucket'
SRC = './test_' + str(int(datetime.now().timestamp()))
NUMDOCS = 3

s3 = boto3.client('s3')

def upload_file(filepath, keyy):
    start = time.time()
    s3.upload_file(filepath, BUCKETNAME, keyy)
    end = time.time()
    print(f"Uploaded: {keyy} ({os.path.getsize(filepath)} bytes) in {end - start:.2f}s")


def upload():
    os.makedirs(SRC)

    # 20 files, each is 10KB
    file_gen(NUMDOCS, 10 * 1024)

    for file in os.listdir(SRC):
        full_path = os.path.join(SRC, file)
        upload_file(full_path, file)
        print("creating storage doc with name " + str(file))
        create_storage_doc(file, uuid.uuid4(), str(file)[:5] + "_file.pdf","my desc " + str(file)[:5], datetime.now(), b'', "pdf", encrypt_data_key("Data Key 16 Char".encode("utf-8"), bytes.fromhex("4F8C484321E430B0DA32642103666D67")), uuid.UUID("D2FD818F-8E06-4688-BCBB-B7926ECF9C34"))

def file_gen(count, size):
    KEY = b"Data Key 16 Char"


    for i in range(count):
        filename = str(uuid.uuid4())

        content_str = ''.join(random.choices(string.ascii_letters + string.digits, k = size))
        content_bytes = content_str.encode('utf-8')

        encrypted_data = encrypt(content_bytes, KEY)

        with open(os.path.join(SRC, filename), 'wb') as f:
            f.write(encrypted_data)

def list_bucket_files():
    paginator = s3.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=BUCKETNAME)

    for page in pages:
        for obj in page.get('Contents', []):
            print(obj['Key'])

def delete_all_objects():
    # Use paginator to handle >1000 objects
    paginator = s3.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=BUCKETNAME)

    delete_us = dict(Objects=[])
    for page in pages:
        for obj in page.get('Contents', []):
            delete_us['Objects'].append(dict(Key=obj['Key']))

            # Delete in batches of 1000 (S3 limit)
            if len(delete_us['Objects']) == 1000:
                s3.delete_objects(Bucket=BUCKETNAME, Delete=delete_us)
                delete_us = dict(Objects=[])

    # Delete any remaining files
    if delete_us['Objects']:
        s3.delete_objects(Bucket=BUCKETNAME, Delete=delete_us)

    print(f"All objects deleted from bucket: {BUCKETNAME}")

import uuid
import pyodbc
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

TAG_LENGTH = 16  # in bytes
NONCE_LENGTH = 12  # usually 12 bytes for GCM

def encrypt_with_pycryptodome(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LENGTH)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag  # Append tag to ciphertext, like Bouncy Castle's output

def encrypt_data_key(data_key: bytes, master_key: bytes) -> bytes:
    nonce = get_random_bytes(NONCE_LENGTH)
    ciphertext = encrypt_with_pycryptodome(data_key, master_key, nonce)

    # Prepend nonce to ciphertext (with tag)
    encrypted_data_key = nonce + ciphertext
    return encrypted_data_key

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LENGTH = 12  # GCM standard nonce size

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_LENGTH)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return nonce + ciphertext
    
def create_storage_doc(
    pk: uuid.UUID,
    storage_main_pk: uuid.UUID,
    file_name: str,
    desc: str,
    date: datetime,
    data: bytes,
    doc_type: str = "",
    encrypted_data_key: bytes | None = None,
    master_key_pk: uuid.UUID | None = None,
    storage_docs_db_name: str = "DocumentUtil_SD001",
    connection_string: str = "Driver={ODBC Driver 17 for SQL Server};Server=AP-HYB-t0DQoKLP;Database=DocumentUtil_SD001;Trusted_Connection=yes;"
) -> uuid.UUID:
        
    sql = f"""
    INSERT INTO {storage_docs_db_name}.dbo.StorageDocs
    (
        SC_PK,
        SC_SM,
        SC_FileName,
        SC_Date,
        SC_ImageData,
        SC_DocType,
        SC_Desc,
        SC_EncryptedDataKey,
        SC_SCK_MasterKey,
        SC_SystemCreateTimeUtc,
        SC_SystemCreateUser,
        SC_SystemLastEditTimeUtc,
        SC_SystemLastEditUser
    )
    VALUES
    (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, GETUTCDATE(), '~BP', GETUTCDATE(), '~BP'
    )
    """

    # Connect and execute
    with pyodbc.connect(connection_string) as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, (
                pk,
                storage_main_pk,
                file_name,
                date,
                data,
                doc_type or None,
                desc,
                encrypted_data_key,
                master_key_pk
            ))
            conn.commit()
    
    return pk
    

if __name__ == '__main__':
    # list_bucket_files()
    # delete_all_objects()
    print("Preparing S3 Benchmark Upload...")
    upload()
    print("Upload complete.")
