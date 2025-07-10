from tkinterdnd2 import TkinterDnD
from gui import HasherGUI

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = HasherGUI(root)
    root.mainloop()