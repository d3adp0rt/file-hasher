import os
from tkinter import Label, Text, Scrollbar, Button, END, filedialog, Frame, Tk, StringVar
from tkinter.ttk import Combobox, Progressbar
from tkinterdnd2 import DND_FILES, TkinterDnD

from logic import compute_file_hash, load_algos

class HasherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Drag-and-Drop File Hasher")
        self.root.geometry('600x400')

        self.algo_var = StringVar()
        self.progress = Progressbar(root, mode='determinate', length=500)

        self.setup_widgets()

    def setup_widgets(self):
        label = Label(self.root, text="Drag and drop a file here or use 'Browse'", bg='lightgray', width=60, height=5)
        label.pack(pady=10)
        label.drop_target_register(DND_FILES)
        label.dnd_bind('<<Drop>>', self.drop_file)

        algo_box = Combobox(self.root, textvariable=self.algo_var, values=load_algos(), state='readonly')
        algo_box.set('sha256')
        algo_box.pack(pady=5)

        btn_frame = Frame(self.root)
        btn_frame.pack(pady=5)

        browse_btn = Button(btn_frame, text='Browse File', command=self.browse_file)
        browse_btn.pack(side='left', padx=5)

        self.copy_btn = Button(btn_frame, text='Copy Result', command=self.copy_result, state='disabled')
        self.copy_btn.pack(side='left', padx=5)

        self.progress.pack(pady=5)

        text_frame = Frame(self.root)
        text_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.hash_output = Text(text_frame, wrap='char', state='disabled', height=10)
        scrollbar = Scrollbar(text_frame, command=self.hash_output.yview)
        self.hash_output.config(yscrollcommand=scrollbar.set)
        self.hash_output.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.handle_file(file_path)

    def drop_file(self, event):
        path = event.data.strip('{}')
        if os.path.isfile(path):
            self.handle_file(path)

    def handle_file(self, path):
        try:
            self.hash_output.config(state='normal')
            self.hash_output.delete(1.0, END)

            def update_progress(value):
                self.progress['value'] = value
                self.root.update_idletasks()

            file_hash = compute_file_hash(path, self.algo_var.get(), update_progress)

            result = f"File: {path}\nAlgorithm: {self.algo_var.get()}\nHash:\n{file_hash}"
            self.hash_output.insert(END, result)

            self.copy_btn.config(state='normal')
        except Exception as e:
            self.hash_output.insert(END, f"[ERROR]: {e}")
        finally:
            self.hash_output.config(state='disabled')
            self.progress['value'] = 0

    def copy_result(self):
        text = self.hash_output.get(1.0, END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
