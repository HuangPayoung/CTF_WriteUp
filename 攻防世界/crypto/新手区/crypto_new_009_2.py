import base64

final = 'UC7KOWVXWVNKNIC2XCXKHKK2W5NLBKNOUOSK3LNNVWW3E==='
s1 = base64.b32decode(final)
s1 = '\xa0\xbe\xa7Z\xb7\xb5Z\xa6\xa0Z\xb8\xae\xa3\xa9Z\xb7Z\xb0\xa9\xae\xa3\xa4\xad\xad\xad\xad\xad\xb2'
s2 = ''
s3 = ''

for i in s1:
    i = (ord(i) ^ 36) - 36
    s2 += chr(i)

for i in s2:
    i = (ord(i) - 25) ^ 36
    s3 += chr(i)

print(s3)