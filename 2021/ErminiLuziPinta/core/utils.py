import curses

def colors(line, column, txt, rgb):
    try:
        stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()

        for i in range(0, 255):
            curses.init_pair(i + 1, i, -1)

        stdscr.addstr(line, column, txt, curses.color_pair(rgb))
        stdscr.refresh()
    except:
        pass

def clean_line_end():

    for i in range(1,8):
        stdscr = curses.initscr()       
        stdscr.addstr(i, 0,'                                                ')
        stdscr.refresh()

