s = 'b0a468c2ce84a2d29a84de6a98526e'
d = []
l = []
j = []

for i in range (0, len(s)):
    d.append(s[i])
print(d)
for q in range(len(d)):
    if q % 2 == 0:
        l.append(''.join(d[q:q+2]))
print(l)
for i in range(len(l)):
    a = l[i]
    b = int(a, 16)
    c = b//2
    print(c)
    d = chr(c)
    print(d)
    j.append(d)
g = ''.join(j)
print(g)