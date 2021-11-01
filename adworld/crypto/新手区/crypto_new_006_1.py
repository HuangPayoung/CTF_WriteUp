s = '8842101220480224404014224202480122'
s1 = s.split('0')
re = ''
for i in range(len(s1)):
    tmp = 0
    for j in range(len(s1[i])):
        tmp += int(s1[i][j])
    tmp %= 26
    re += chr(tmp + 64)

print(re)