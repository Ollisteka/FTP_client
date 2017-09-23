#!/usr/bin/env python
# Tkinter (Tk/Ttk) Progressbar widget example
#
# Written by Yu-Jie Lin
# This code is placed in Public Domain
#
# Gist: https://gist.github.com/livibetter/6850443
# Clip: https://www.youtube.com/watch?v=rKr8wjKuhBY
#
# References:
#
#   * http://docs.python.org/2/library/ttk.html#progressbar
#   * http://docs.python.org/3/library/tkinter.ttk.html#progressbar
#
# Backstory:
#
# I wrote this script because one [1] of my videos got some hits with
# irrelevant keywords. I understand that would be frustrating when the searcher
# wants to find a progress bar in Tk, but gets a video hit about progress bar
# in terminal. So I did some reading and coding to produce this code.
#
# [1]: https://www.youtube.com/watch?v=goeZaYERNnM


try:
    import Tkinter              # Python 2
    import ttk
except ImportError:
    import tkinter as Tkinter   # Python 3
    import tkinter.ttk as ttk


def main():

    root = Tkinter.Tk()

    ft = ttk.Frame()
    ft.pack(expand=True, fill=Tkinter.BOTH, side=Tkinter.TOP)
    pb_hd = ttk.Progressbar(ft, orient='horizontal', mode='determinate')
    pb_hd.pack(expand=True, fill=Tkinter.BOTH, side=Tkinter.TOP)
    pb_hd.start(10)
    root.mainloop()


if __name__ == '__main__':
  main()