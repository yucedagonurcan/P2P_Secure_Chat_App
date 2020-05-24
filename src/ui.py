COLORS = {"green" : "\33[92m",
          "red"   : "\33[91m",
          "yellow" : "\33[93m",
          "endc"    : "\33[0m" }


def print_green(msg):
    """Prints msg in green text."""
    print("{0}{1}{2}".format(COLORS["green"], msg, COLORS["endc"]))


def print_yellow(msg):
    """Prints msg in yellow text."""
    print("{0}{1}{2}".format(COLORS["yellow"], msg, COLORS["endc"]))


def print_red(msg):
    """Prints msg in red text."""
    print("{0}{1}{2}".format(COLORS["red"], msg, COLORS["endc"]))


def print_banner(message):
    """Prints the entry banner."""
    print_green("///////////////////")
    print_green(f"// {message} //")
    print_green("///////////////////")

def print_bar(msg):
    print("-"*(31 - int(.5 * len(msg))), msg, "-"*(31 - int(.5 * len(msg))))
