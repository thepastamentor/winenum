import os
from winenum.core.console import print_status

def save_to_file(output_dir: str, filename: str, content: str, mode: str = 'w') -> str:
    """Save content to output directory"""
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)
    with open(filepath, mode) as f:
        f.write(content)
    return filepath

def save_hash(output_dir: str, hash_str: str, hash_type: str):
    """Save hash to file for cracking"""
    filepath = save_to_file(output_dir, f'{hash_type}_hashes.txt', hash_str + '\n', 'a')
    print_status(f"  Hash saved to {filepath}", "info")
