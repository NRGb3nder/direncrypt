# direncrypt
OS and System Programming, lab #5

Write a program to encrypt all files of a directory and all its subdirectories. The path to the directory is specified by user. The main thread opens directory and runs encrypter thread for each file. Any other thread prints its id, real path to processed file and total number of encrypted bytes. Use xor with bits of key file as a cipher algorithm.

Command format:
```
<program> <directory_to_encrypt> <output_directory> <key_file> <max_number_of_threads>
```
