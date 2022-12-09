#!/usr/bin/env python

"""
IATelligence: A Python script that extracts the IAT from a PE file 
and requests OpenAI for more details.

Author: Thomas Roccia | @fr0gger_
"""

import sys
import hashlib
import pefile
import openai
import tqdm

from prettytable import PrettyTable

# Authenticate with the OpenAI API
openai.api_key = ""

def calculate_hashes(file):
    """
    calculate the MD5, SHA1, and SHA256 hashes of a file.
    
    :param file: The file to be hashed.
    :return: A dictionary containing the MD5, SHA1, and SHA256 hashes of the file.
    """
    # Create a dictionary to store the hashes
    hashes = {}
    
    with open(file, "rb") as pef:
        # Calculate the MD5 hash
        md5 = hashlib.md5()
        md5.update(pef.read())
        hashes["md5"] = md5.hexdigest()
        
        # Calculate the SHA1 hash
        pef.seek(0) 
        sha1 = hashlib.sha1()
        sha1.update(pef.read())
        hashes["sha1"] = sha1.hexdigest()
        
        # Calculate the SHA256 hash
        pef.seek(0)
        sha256 = hashlib.sha256()
        sha256.update(pef.read())
        hashes["sha256"] = sha256.hexdigest()
        
    return hashes

def extract_iat(pe):
    """
    Extract the Import Address Table (IAT) entries from a PE file.

    :param pe: The PE file to extract the IAT entries from.
    :return: A dictionary of IAT entries, where the keys are 
    the imported function names and the values are the DLL names.
    """

    # Create an empty dictionary to store the IAT entries
    iat = {}

    # Retrieve the IAT entries from the PE file
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            dll_name = entry.dll
            imp_name = imp.name
            # Store the IAT entry in the dictionary
            iat[imp_name] = dll_name
    
    return iat

def request_openai(iat):
    """
    Use the OpenAI API to analyze the imported function names 
    and DLL names in a dictionary of IAT entries.

    :param iat: A dictionary of IAT entries, where the keys are 
    the imported function names and the values are the DLL names.
    :return: A list of lists containing the DLL names, imported 
    function names, and OpenAI API responses for each IAT entry.
    """
    # Calculate the estimated cost of the requests
    estimated_cost = len(iat) * 0.0021

    # Print the estimated cost above the progress bar
    print(f"[!] Estimated cost of requests: ${estimated_cost}\n")
     
    # Create an empty list to store the OpenAI API responses
    gptable = []

    with tqdm.tqdm(total=len(iat)) as pbar:
        # Loop through the IAT entries in the dictionary
        for imp_name, dll_name in iat.items():
            # Create a prompt for the OpenAI API with the DLL name and imported function name
            prompt = f"What is the purpose of this API, is there a MITRE ATT&CK technique associated and why: '{dll_name}: {imp_name}'?"
            result = openai.Completion.create(
                engine="text-davinci-003",
                max_tokens=2500,
                top_p=1,
                frequency_penalty=1,
                presence_penalty=1,
                prompt=prompt,
                temperature=0.6
                )

            gptable.append([dll_name.decode('utf-8'), imp_name.decode('utf-8'), result["choices"][0]["text"].strip() + "\n"])

            pbar.update(1)

    return gptable


def main():
    """
    Analyze the Import Address Table (IAT) entries in a 
    PE file using the OpenAI API.
    The PE file to analyze must be provided as an argument 
    when running the script.
    """

    # Check that a file was provided as an argument
    if len(sys.argv) < 2:
        print("[!] Usage: python iatelligence.py <executable_file>")
        return
   
    print("[+] IAT Request from the file: " + sys.argv[1])

    # Open the PE file and extract the IAT
    try:
        pe = pefile.PE(sys.argv[1])
        hashes = calculate_hashes(sys.argv[1])
        iat = extract_iat(pe)
        print(f"[+] {len(iat)} functions will be requested to GPT!")
        print(f"[+] MD5: {hashes['md5']}")
        print(f"[+] SHA1: {hashes['sha1']}")
        print(f"[+] SHA256: {hashes['sha256']}")
        print(f"[+] Imphash: {pe.get_imphash()}")

    except OSError as error:
        print(error)
        sys.exit()
    except pefile.PEFormatError as error:
        print(f"[-] PEFormatError: %s {error.value}")
        print("[!] The file is not a valid PE")
        sys.exit()

    # Request Openai and store in a list
    gptable = request_openai(iat)

    # Pretty print the table with the result
    tabres = PrettyTable(["Libraries", "API", "GPT Verdict"],  align='l', max_width=40)

    for (dll_name, imp_name, gptverdict) in gptable:
        tabres.add_row([dll_name, imp_name, gptverdict])

    print(tabres)


if __name__ == "__main__":
    main()
