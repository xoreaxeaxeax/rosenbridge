import os

NAME = "monitor"
clients = [0, 1, 2, 3, 4, 5, 6, 7]

screen = ""

WIDTH = 4
HEIGHT = 2

with open("tmp", "w") as f:

    f.write("sorendition wK\n") # white on bold black

    for _ in xrange(HEIGHT - 1):
        f.write("split\n");

    for _ in xrange(HEIGHT):
        for _ in xrange(WIDTH - 1):
            f.write("split -v\n")
        f.write("focus down\n")

    f.write("focus top\n")

    for c in clients:
        f.write("screen -t %s tail -f device_%d.log\n" % (c, c))
        f.write("focus\n") # focus to next region

os.system("screen -c tmp")
