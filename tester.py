import shutil
import os
import stat

def force_remove_folder(folder):
    def onerror(func, path, exc_info):
        os.chmod(path, stat.S_IWRITE)  # remove read-only flag
        func(path)
        
    shutil.rmtree(folder, onerror=onerror)

force_remove_folder('keys')