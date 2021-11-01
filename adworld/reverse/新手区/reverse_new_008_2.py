import base64

def decode(message):
    s = base64.b64decode(message)
    re = ''
    for i in s:
        x = i - 16
        x = x ^ 32
        re += chr(x)

    return re

correct = 'XlNkVmtUI1MgXWBZXCFeKY+AaXNt'
flag = decode(correct)
print(flag)