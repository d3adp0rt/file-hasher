import hashlib
import os
from tkinter import Label, Text, Scrollbar, Button, END, filedialog, Frame, Tk, StringVar
from tkinter.ttk import Combobox, Progressbar
from tkinterdnd2 import DND_FILES, TkinterDnD

# Load available hashing algorithms from file or default list
def load_algos(path='algos.txt'):
    try:
        with open(path, 'r') as f:
            algos = f.read().split()
        # Return only supported algorithms
        return [algo for algo in algos if algo in hashlib.algorithms_available]
    except FileNotFoundError:
        return ['sha256', 'sha1', 'md5']

# Compute file hash with progress update
def get_file_hash(path, algo='sha256') -> str:
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"Algorithm {algo} not supported")
    hash_func = hashlib.new(algo)
    total_size = os.path.getsize(path)
    processed = 0

    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
            processed += len(chunk)
            # Update progress bar
            progress['value'] = (processed / total_size) * 100
            root.update_idletasks()

    return hash_func.hexdigest()

# Handle file input (drag-and-drop or browse)
def handle_file(path):
    try:
        hash_output.config(state='normal')
        hash_output.delete(1.0, END)

        # Compute hash and display full string, widget will wrap
        file_hash = get_file_hash(path, algo_var.get())
        output_str = (
            f"File: {path}\n"
            f"Algorithm: {algo_var.get()}\n"
            f"Hash:\n{file_hash}"
        )
        hash_output.insert(END, output_str)

        copy_btn.config(state='normal')
    except Exception as e:
        hash_output.insert(END, f"[ERROR]: {e}")
    finally:
        hash_output.config(state='disabled')
        progress['value'] = 0

# Drag-and-drop callback
def drop(event):
    file_path = event.data.strip('{}')
    if os.path.isfile(file_path):
        handle_file(file_path)

# Browse button callback
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        handle_file(file_path)

# Copy result to clipboard
def copy_hash():
    text = hash_output.get(1.0, END).strip()
    root.clipboard_clear()
    root.clipboard_append(text)

# Initialize main window
root = TkinterDnD.Tk()
root.title("Drag-and-Drop File Hasher")
root.geometry('600x400')

# Instruction label
label = Label(root, text="Drag and drop a file here or use 'Browse'", bg='lightgray', width=60, height=5)
label.pack(pady=10)
label.drop_target_register(DND_FILES)
label.dnd_bind('<<Drop>>', drop)

# Algorithm selection dropdown
algo_var = StringVar()
algo = Combobox(root, textvariable=algo_var, values=load_algos(), state='readonly')
algo.set('sha256')
algo.pack(pady=5)

# Buttons frame
btn_frame = Frame(root)
btn_frame.pack(pady=5)

browse_btn = Button(btn_frame, text='Browse File', command=browse_file)
browse_btn.pack(side='left', padx=5)

copy_btn = Button(btn_frame, text='Copy Result', command=copy_hash, state='disabled')
copy_btn.pack(side='left', padx=5)

# Progress bar
progress = Progressbar(root, mode='determinate', length=500)
progress.pack(pady=5)

# Text widget with char wrap for better line breaks
text_frame = Frame(root)
text_frame.pack(fill='both', expand=True, padx=10, pady=10)

hash_output = Text(text_frame, wrap='char', state='disabled', height=10)
scrollbar = Scrollbar(text_frame, command=hash_output.yview)
hash_output.config(yscrollcommand=scrollbar.set)
hash_output.pack(side='left', fill='both', expand=True)
scrollbar.pack(side='right', fill='y')

root.mainloop()
