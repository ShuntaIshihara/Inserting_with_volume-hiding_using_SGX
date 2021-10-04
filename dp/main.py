import sys
import table

def main(args):
    readfile = open(args[1], "r", encoding="utf_8")

    line = readfile.readline()
    print(line)
    t = table.Table(int(line))

    line = readfile.readline()
    while line:
        t.addDP(int(line))
        t.addLDP(int(line))

        line = readfile.readline()
    readfile.close()

    epsilon = 1.0
    t.applyDP(epsilon)

    t.printMax()
    t.printMin()
    t.printMean()
    t.drawHistogram()


if __name__ == '__main__':
    args = sys.argv

    if (len(args) != 2):
        print("Error: コマンドライン引数")
        sys.exit()

    main(args)