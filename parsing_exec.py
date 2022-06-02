import pefile
import glob
import json
import string
import time
import validators

def get_strings(filename, min=4):
    with open(filename, errors="ignore") as f:
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result

print("""
 ____  ____   ___   ____    ___ ______       _____   ___    __ 
|    \|    \ /   \ |    |  /  _]      |     / ___/  /  _]  /  ]
|  o  )  D  )     ||__  | /  [_|      |    (   \_  /  [_  /  / 
|   _/|    /|  O  |__|  ||    _]_|  |_|     \__  ||    _]/  /  
|  |  |    \|     /  |  ||   [_  |  |       /  \ ||   [_/   \_ 
|  |  |  .  \     \  `  ||     | |  |       \    ||     \     |
|__|  |__|\_|\___/ \____||_____| |__|        \___||_____|\____|
                                                                         
                                                                    """)

print("By FELLAG Asma & Belacel Neila")

print("------------------------------ \n \n")

print("[*] Projet 3 du module de sécurité informatique")

print("-------------------------------------------------------")

print("Titre : Executable Parser and malware checker")

print("-------------------------------------------------------")


exe_path = "chrome.exe"
pe = pefile.PE(exe_path)  

functions = []


print("1 - Listing imports -----------------")
pe.parse_data_directories()

time.sleep(1)

for entry in pe.DIRECTORY_ENTRY_IMPORT:  
  print(entry.dll)
  for imp in entry.imports:
    print('\t', hex(imp.address), imp.name.decode('utf-8'))
    functions.append(imp.name.decode('utf-8'))

print("[*] Listing imported DLLs...")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('\t' + entry.dll.decode('utf-8')) 

print("-----------------------------")

print("2 - Listing exports -----------------")

time.sleep(1)

for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name.decode('utf-8'))
    functions.append(imp.name.decode('utf-8'))

print("-----------------------------")

print("3 - Extracting strings --------------")

time.sleep(1)

pe_strings = list(get_strings(exe_path))

print(pe_strings)


print("-----------------------------")
print("Extract Link's from strings")
print("-----------------------------")

time.sleep(1)

for s in pe_strings:

    valid=validators.url(s)
    if valid:
        print(s)

print("[*] Functions in export and import :")

time.sleep(1)

malicious_functions = ["CreateFile", "CreateProcess", "InternetOpen"] # Just some few examples.


print(functions)

for i in functions:
    if i in malicious_functions:
        print("[-] Alert !!! Possibilité de malware !")
        break