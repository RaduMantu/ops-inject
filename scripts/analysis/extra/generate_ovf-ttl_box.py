#!/usr/bin/python3

import sys
import numpy as np
import matplotlib

matplotlib.use("pgf")
matplotlib.rcParams.update({
    "pgf.texsystem": "pdflatex",
    'font.family': 'serif',
    'text.usetex': True,
    'pgf.rcfonts': False,
})

import matplotlib.pyplot as plt

# takes as input an number of file names containing
#   "tll ovf"
# pairs; one per line
#
# NOTE: add 4 to every ovf to get number of actual interfaces

def main():
    # argument check
    if len(sys.argv) == 0:
        print('give input file as argument')
        return -1

    # create { ttl_delta : [ ts_hops ] } dictionary
    d = {}

    # for each input file
    for imp in sys.argv[1:]:
        with open(imp, 'r') as f:
            lines = f.readlines()

            for line in lines:
                # extract numbers from string
                line = line.replace('\t', '').replace('\n', '').split(' ')
                ttl_delta, ovf = tuple(map(lambda x: int(x), 
                                           filter(lambda x: x != '',
                                                  line)))

                # if first ttl delta encountered
                if ttl_delta not in d:
                    d[ttl_delta] = []

                # update dict with actual values
                # this +4 is a bit hardcoded but we don't have short paths -> ok
                d[ttl_delta].append(ovf + 4)

    # extract data in order from dict
    data = [d[it] if it in d else [] for it in range(1, max(d.keys()) + 1)]

    # print data for debug
    for it in range(0, max(d.keys())):
        print(it + 1, data[it])

    # f(x) = x; to show distance from actual value
    linsc = list(range(1, max(d.keys()) + 1))

    # plot data
    fig, ax = plt.subplots()
    ax.boxplot(data)
    ax.plot(linsc, linsc, 'bx')

    ax.set_xlabel('Number of TTL hops', fontsize=16)
    ax.set_ylabel('Timestamp addition attempts', fontsize=16)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    ax.grid(True, which='major', axis='y')

    plt.savefig('ttl-ovf.pgf')

    #plt.show()

    return 0


if __name__ == '__main__':
    ans = main()
    exit(ans)
