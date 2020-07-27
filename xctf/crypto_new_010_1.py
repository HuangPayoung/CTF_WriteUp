s1 =  'ZWAXJGDLUBVIQHKYPNTCRMOSFE'
s2 =  'KPBELNACZDTRXMJQOYHGVSFUWI'
s3 =  'BDMAIZVRNSJUWFHTEQGYXPLOCK'
s4 =  'RPLNDVHGFCUKTEBSXQYIZMJWAO'
s5 =  'IHFRLABEUOTSGJVDKCPMNZQWXY'
s6 =  'AMKGHIWPNYCJBFZDRUSLOQXVET'
s7 =  'GWTHSPYBXIZULVKMRAFDCEONJQ'
s8 =  'NOZUTWDCVRJLXKISEFAPMYGHBQ'
s9 =  'XPLTDSRFHENYVUBMCQWAOIKZGJ'
s10 = 'UDNAJFBOWTGVRSCZQKELMXYIHP'
s11 = 'MNBVCXZQWERTPOIUYALSKDJFHG'
s12 = 'LVNCMXZPQOWEIURYTASBKJDFHG'
s13 = 'JZQAWSXCDERFVBGTYHNUMKILOP'

cry = 'NFQKSEVOQOFNP'
re = ''
s = [s2, s3, s7, s5, s13, s12, s9, s1, s8, s10, s4, s11, s6]

for i in range(len(s)):
    index = s[i].find(cry[i])
    s[i] = (s[i][index:] + s[i][0:index]).lower()

for i in range(1, 26):
    t = ''
    for j in s:
        t += j[i]
    print(t) 
        
print(re)