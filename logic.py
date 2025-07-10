import hashlib
import os, sys

def resource_path(relative):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative)
    return os.path.join(os.path.abspath("."), relative)

def load_algos(path='algos.txt'):
    path = resource_path(path)
    try:
        with open(path, 'r') as f:
            algos = f.read().split()
        return [algo for algo in algos if algo in hashlib.algorithms_available]
    except FileNotFoundError:
        return ['sha256', 'sha1', 'md5']

def compute_file_hash(path, algo='sha256', progress_callback=None):
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"Algorithm {algo} not supported")

    hash_func = hashlib.new(algo)
    total_size = os.path.getsize(path)
    processed = 0

    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed / total_size * 100)

    return hash_func.hexdigest()
