#!/usr/bin/env python3

"""Addresses filter"""
import imaplib
import datetime
import email
import email.message
import time
import json
import os.path
import re
import sys
import secrets
import socket
import base64
import traceback
import validators
import random
import pathlib
from hashlib import md5
import platform
from os import listdir, sep, mkdir
from os.path import isfile, join, dirname, exists
import smtplib
import logging
import paramiko
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

IDENT = md5(';fadkjdf;lajkdf'.encode('UTF-8')).hexdigest()

if platform.system() == 'Linux':
    try:
        lock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        lock.bind(f'\0{IDENT}')
        print('First instance starts')
    except Exception as ex: # pylint: disable=broad-exception-caught
        print("Can't start. Something went wrong")
        print(f"Exception is {str(ex)}. Exit")
        sys.exit()

#if plat == 'Linux':
#    import syslog
#    from Crypto.Cipher import AES
#    from Crypto import Random
#    from M2Crypto import SMIME
#    from M2Crypto import X509
#    from M2Crypto import BIO

# TODO: correct paths
# constants
imaplib._MAXLINE = 1000000 # pylint: disable=protected-access

APP_TMT = 60
LOG_START_TIME = re.sub(r"\W+", "_", str(time.ctime()))
LOG_FMT_STRING = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

if getattr(sys, 'frozen', False):
    app_path = dirname(sys.executable)
    app_name = pathlib.Path(sys.executable).stem
    APP_RUNMODE = 'PROD'
    time.sleep(APP_TMT)
else:
    app_path = os.path.dirname(os.path.abspath("__file__"))
    app_name = pathlib.Path(__file__).stem
    APP_RUNMODE = 'TEST'
INPUT_DIR = f'{app_path}{sep}servers{sep}'
LOG_DIR = f'{app_path}{sep}logs'

if not exists(LOG_DIR):
    try:
        mkdir(LOG_DIR)
    except Exception as ex: # pylint: disable=broad-exception-caught
        print('Log directory creation fails. Exit')
        sys.exit()
LOG_FILENAME = f'{LOG_DIR}{sep}{app_name}_{LOG_START_TIME}.log'
log_handlers = [logging.StreamHandler(),logging.FileHandler(LOG_FILENAME)]


logger = logging.getLogger(APP_RUNMODE)
logging.basicConfig(format=LOG_FMT_STRING,
                    datefmt='%d.%m.%Y %H:%M:%S',
                    level=logging.INFO, # NOTSET/DEBUG/INFO/WARNING/ERROR/CRITICAL
                    handlers=log_handlers)

for el in [INPUT_DIR]:
    if not exists(el):
        try:
            Path(el).mkdir(parents=True, exist_ok=True)
        except Exception as ex:
            logger.critical("Can't create input directories")
            sys.exit()
try:
    with open(f"{app_path}{sep}{app_name}.config", 'r', encoding='UTF-8') as cf:
        conf = json.load(cf)
except Exception as ex: # pylint: disable=broad-exception-caught
    logger.critical("No config file found or it's not a valid json")
    sys.exit()

try:
    mail_server = conf['mail_server']
    mail_l = conf['mail_l']
    mail_p = conf['mail_p']
    mail_to = conf['mail_to']
    got_from = conf['got_from']
    enc_key = conf['enc_key']
    enc_iv = conf['enc_iv']
    mktk_p = conf['mktk_p']
    mktk_server = conf['mktk_server']
    mktk_port = conf['mktk_port']
    mktk_u = conf['mktk_u']
except Exception as ex: # pylint: disable=broad-exception-caught
    logger.critical("Some necessary configuration parameters not found")
    logger.critical("Exception is %s", str(ex))
    sys.exit()

if not validators.url(f"https://{mail_server}"):
    logger.critical("Mail server is incorrect. Exit")
    sys.exit()
if not validators.email(mail_l):
    logger.critical("Email used as login is incorrect. Exit")
    sys.exit()
if not validators.email(mail_to):
    logger.critical("Email used as destinatioin is incorrect. Exit")
    sys.exit()
if not validators.email(got_from):
    logger.critical("Email used as source is incorrect. Exit")
    sys.exit()
    
def decrypt(ciphertext, password):
    """Decription Crypto-JS compatible"""
    encryptedData = base64.b64decode(ciphertext) # pylint: disable=invalid-name

    salt = encryptedData[8:16]
    ciphertext = encryptedData[16:]
    ciphertext = encryptedData

    derived = b""
    while len(derived) < 48:  # "key size" + "iv size" (8 + 4 magical units = 12 * 4 = 48)
        hasher = MD5.new()
        hasher.update(derived[-16:] + password.encode('utf-8') + salt)
        derived += hasher.digest()

    #key = '0A2h4m6Kj701s34m'.encode('UTF-8')
    key = f'{enc_key}'.encode('UTF-8')
    #iv = 'H4t21t9N7k5L32N8'.encode('UTF-8')
    iv = f'{enc_iv}'.encode('UTF-8')

    # Decrypt the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), 16)
    return decrypted.decode('utf-8')

def encrypt(plaintext, password):
    """Crypto-JS encryption compatible"""
    salt = secrets.token_bytes(8)

    derived = b""
    while len(derived) < 48:  # "key size" + "iv size" (8 + 4 magical units = 12 * 4 = 48)
        hasher = MD5.new()
        hasher.update(derived[-16:] + password.encode('utf-8') + salt)
        derived += hasher.digest()

    # key = derived[0:32]
    # key = '0A2h4m6Kj701s34m'.encode('UTF-8')
    key = f'{enc_key}'.encode('UTF-8')
    # iv = derived[32:48]
    # iv = 'H4t21t9N7k5L32N8'.encode('UTF-8')
    iv = f'{enc_iv}'.encode('UTF-8')

    # Encrypt the plaintext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode('utf-8'), 16))
    print('Some fuck')
    print(base64.b64encode(encrypted))
    # Combine salt and encrypted data
    # encrypted_bytes = base64.b64encode(b'Salted__' + salt + encrypted)
    return base64.b64encode(encrypted)
    
def ssh_connect(host, port, username, password):
    """Establish SSH connection to MikroTik."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=username, password=password,look_for_keys=False)
    return client

def exec_command(ssh_client, command):
    """Execute command on MikroTik via SSH and return output."""
    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    return output, error
    
def save_mails(in_mail_server, in_mail_l, in_mail_p):
    """Download emails"""
    logger.info('Connecting to %s', in_mail_server)
    imap = imaplib.IMAP4_SSL(in_mail_server)
    logger.info('Connected! Logging in as  %s', in_mail_l)
    imap.login(in_mail_l, in_mail_p)
    logger.info("Logged in! Listing messages...")
    status, select_data = imap.select('INBOX')
    logger.info("Status is %s", status)
    nmessages = select_data[0].decode('utf-8')
    l_time = datetime.datetime.strftime(datetime.datetime.now(), '%d-%b-%Y')
    status, search_data = imap.search(None, f'FROM "{got_from}" SINCE {l_time}')
    for msg_id in search_data[0].split():
        msg_id_str = msg_id.decode('utf-8')
        logger.info("Fetching message %s of %s", msg_id_str, nmessages)
        status, msg_data = imap.fetch(msg_id, '(RFC822)')
        msg_raw = msg_data[0][1]
        msg = email.message_from_bytes(msg_raw, _class = email.message.EmailMessage)
        if 'subject' in msg['Subject']:
            attach = msg.get_payload()[1]
            attach = attach.get_payload(decode=True)
            vy_password = "some password"
            # decrypted = decrypt(ciph_text, vy_password)
            decrypted = decrypt(attach, vy_password)
            print("Decrypted ciphertext (base64):", decrypted)
            decrypted = base64.b64decode(decrypted)
            try:
                open(INPUT_DIR+msg['Subject'], 'wb').write(decrypted)
            except Exception as ex: # pylint: disable=broad-exception-caught
                logger.critical("Can't create write into input directories")
                logger.critical("Exception is %s", str(ex))
                sys.exit()
            time.sleep(5)
        continue
    imap.logout()

def send_email(in_mail_server, in_mail_l, in_mail_p,
               in_mail_to, in_mail_sub, in_mail_body):
    """Simple SMTP sending function"""
    from_mbox = in_mail_l
    if type(in_mail_to) is list:
        mlist = in_mail_to
    else:
        mlist = [in_mail_to]
    to = mlist
    subject = in_mail_sub
    if in_mail_body:
        text = in_mail_body
    else:
        text = 'No body provided'
    message = ('From: %s\n'
               'To: %s\n'
               'Subject: %s\n\n%s') % (from_mbox, ", ".join(to), subject, text)
    try:
        server = smtplib.SMTP(in_mail_server, 587)
        server.ehlo()
        server.starttls()
        server.login(in_mail_l, in_mail_p)
        server.sendmail(from_mbox, to, message)
        server.close()
        # mail_counter += 1
    except Exception as ex: # pylint: disable=broad-exception-caught
        logger.info('Connecting to %s', str(ex))
    return True

# see https://stackoverflow.com/a/25457500
# imap.store(msg_id, '+FLAGS', '\\Deleted')
# imap.expunge()


# def sendsmime(from_addr='',
#               to_addrs='',
#               subject='',
#               msg='Test_content',
#               from_key='',
#               from_cert='',
#               to_certs=''):
#         subject = subject+str(time.ctime())
# #        msg_bio = BIO.MemoryBuffer(msg)
#         sign = from_key
#         encrypt = to_certs
#  #       s = SMIME.SMIME()
#         if sign:
#             s.load_key(from_key, from_cert)
#             p7 = s.sign(msg_bio, flags=SMIME.PKCS7_TEXT)
#             msg_bio = BIO.MemoryBuffer(msg)
#         if encrypt:
#             sk = X509.X509_Stack()
#             for x in to_certs:
#                 sk.push(X509.load_cert(x))
#             s.set_x509_stack(sk)
#             s.set_cipher(SMIME.Cipher(crypt_settings['cipher_mode']))
#             tmp_bio = BIO.MemoryBuffer()
#             if sign:
#                 s.write(tmp_bio, p7)
#             else:
#                 tmp_bio.write(msg)
#             p7 = s.encrypt(tmp_bio)
#         out = BIO.MemoryBuffer()
#         out.write('From: %s\r\n' % from_addr)
#         out.write('To: %s\r\n' % string.join(to_addrs, ", "))
#         out.write('Subject: %s\r\n' % subject)
#         if encrypt:
#             s.write(out, p7)
#         else:
#             if sign:
#                 s.write(out, p7, msg_bio, SMIME.PKCS7_TEXT)
#             else:
#                 out.write('\r\n')
#                 out.write(msg)
#         out.close()
#         smtp = smtplib.SMTP(mail_cfg['smtp_server'], 587)
#         smtp.ehlo()
#         smtp.starttls()
#         smtp.login(mail_cfg['mail_login'], mail_cfg['mail_password'])
#         smtp.sendmail(from_addr, to_addrs, out.read())
#         smtp.quit()

while True:
    result_gates = []
    save_mails(mail_server, mail_l, mail_p)
    try:
        logger.info('Searching files in INPUT directory %s', INPUT_DIR)
        onlyfiles = [f for f in listdir(INPUT_DIR) if isfile(join(INPUT_DIR, f))]
        actual_files = max([int(af.split('_')[1]) for af in onlyfiles if 'subject' in af])
        actual_file = [af for af in onlyfiles if str(actual_files) in af]
        direct_file = f"{INPUT_DIR}{actual_file[0]}" # pylint: disable=invalid-name
        logger.info('Needed file is %s', direct_file)
        direct_file_out = f"{INPUT_DIR}{actual_file[0]}_out_{str(random.randint(0, 1000))}.txt" # pylint: disable=invalid-name
        logger.info('Needed output file is %s', direct_file_out)
        with open(direct_file, 'r', errors='ignore') as file: # pylint: disable=unspecified-encoding
            data_r = file.read()
        data_r = re.findall(r'[0-9]+(?:\.[0-9]+){3}', data_r)
    except Exception as ex: # pylint: disable=broad-exception-caught
        logger.warning(str(ex))
        logger.warning(traceback.format_exc())
        time.sleep(3)
        continue
    for gate_address in data_r:        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((gate_address, 443))
        if result == 0:
            ssh_client = ssh_connect(mktk_server, mktk_port, mktk_u, mktk_p)
            logger.info("Connected to MikroTik")
            add_sstp_cmd = (
                            f"/interface sstp-client add "
                            f"name=sstp-out "
                            f"connect-to={gate_address} "
                            f"user=vpn "
                            f"password=vpn "
                            f"verify-server-address-from-certificate=no "
                            f"disabled=no"
                           )
            logger.info("Adding SSTP client interface...")
            exec_command(ssh_client, add_sstp_cmd)
            logger.info('SSTP created')
            time.sleep(5)
            check_sstp_cmd = (
                            f"/interface sstp-client monitor 0 once"
                           )
            out, err = exec_command(ssh_client, check_sstp_cmd)
            logger.info('SSTP checked')
            a = []
            if 'connected' in out:
                logger.info('SSTP done')
                rm_sstp_cmd = (
                                f"/interface sstp-client remove 0"
                               )
                out, err = exec_command(ssh_client, rm_sstp_cmd)
            else:
                logger.info('SSTP not done')
                rm_sstp_cmd = (
                                f"/interface sstp-client remove 0"
                               )
                out, err = exec_command(ssh_client, rm_sstp_cmd)
                continue
            str_out = f'Gate address is {gate_address}' # pylint: disable=invalid-name
            logger.info(str_out)
            result_gates.append(gate_address)
        else:
            STR_OUT = 'Gate address is FAILED'
            logger.info(STR_OUT)
            continue
        sock.close()
    logger.info('Try to create %s', direct_file_out)
    with open(direct_file_out, 'w') as file: # pylint: disable=unspecified-encoding
        DATA_W = '\n'.join(result_gates)
        file.write(DATA_W)
    send_email(mail_server, mail_l, mail_p, mail_to, 'sub_some', DATA_W)
    STR_OUT = 'State is OK'
    logger.info(STR_OUT)
    time.sleep(3600)
