# IATElligence
IATelligence is a Python script that extracts the Import Address Table (IAT) from a PE file and uses OpenAI's GPT-3 model to provide details about each Windows API imported by the file. The script also searches for related MITRE ATT&CK techniques and explains how the API could potentially be used by attackers. 

It also displays the hashes of the file and estimates the cost of the GPT-3 requests. IATelligence is a proof of concept for using GPT-3 for malware analysis and quickly assessing the behavior of a malware based on its IAT.

Below is a quick example of the result you'll get. Notice that the request can take longer depending of the size of the IAT. 

![iatellifence](iatelligence.gif)

# Getting Started

## Prerequisites

To run this tool you will need an access to the [OpenAi API](https://beta.openai.com/), you will then need to modify the script to add your own API. 

```python
# Authenticate with the OpenAI API
openai.api_key = ""
```

You will also need to install the requirements.

```
pip install -r requirements.txt
```

# Usage

To run the tool just simply specify a PE file as argument to the script. 

```
python iatelligence.py sample.exe
```

The script will also calculate the hashes as well as the estimated cost of the request. 

```
[+] IAT Request from the file: .\sample.exe
[+] 33 functions will be requested to GPT!
[+] MD5: 2f82623f9523c0d167862cad0eff6806
[+] SHA1: 5d77804b87735e66d7d1e263c31c4ef010f16153
[+] SHA256: 9c2c8a8588fe6db09c09337e78437cb056cd557db1bcf5240112cbfb7b600efb
[+] Imphash: 8eeaa9499666119d13b3f44ecd77a729
[!] Estimated cost of requests: $0.0693
```

# Limitations
The cost of using OpenAI's GPT-3 to analyze the imported Windows APIs in a PE file can vary depending on the size of the IAT. While the cost of individual requests is not expensive, the total cost can quickly add up for larger files. The estimated cost provided by the script is an approximation and may vary.

Due to the design of the script, the analysis is performed one API at a time, which can make the process slow. A progress bar is displayed to show the progress of the analysis.

It is important to note that GPT-3 is a language model, so the results may not always be accurate. Additionally, the script provides details about related MITRE ATT&CK techniques without any context, so the information should be carefully considered by a malware analyst.

# Build with

- [OpenAI](https://openai.com/)
- [Pefile](https://github.com/erocarrera/pefile)
- [PrettyTable](https://github.com/jazzband/prettytable)

# Contact

Twitter: [@fr0gger_](https://twitter.com/fr0gger_)