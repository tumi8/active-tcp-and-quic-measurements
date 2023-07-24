import csv
import random

ranges_def = [(1, 200), (200, 1000), (1000, 10000), (10000, 100000), (100000, None)]
domainlist = []

with open("../testfiles/top-1m.csv", 'r') as f:
    toplist = []
    for row in csv.reader(f):
        toplist.append(row)

    for (l, u) in ranges_def:
        domainlist.extend(random.sample(toplist[l - 1:u], 200))

    domainlist.sort(key=lambda e: int(e[0]))

with open("../testfiles/toplist.csv", 'w', newline='') as f:
    w = csv.writer(f)
    for d in domainlist:
        w.writerow(d)
