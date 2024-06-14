# Explora AI-Powered Fuzzing

_I still need to clean up the code, sorry, but it works on my machine :)_

_Yes, I know that the Ghidra step is mocked._

_If this auto write-up generator feature is added to IDA Pro in the future, I want to get internet points._

## Purpose

Explora is the final project for my Minor in Software Reversing and Exploitation. It serves as a proof of concept for a new fuzzing technique `AI-Powered Fuzzing` powered by AI analysis. The script, `main.py`, automates the multi-stage process of interacting with a binary executable, analyzing its behavior, and extracting meaningful insights and flags, typically used for Capture The Flag (CTF) challenges. It aims to streamline the workflow of binary interaction, decompilation, fuzzing, and analysis, culminating in the generation of a detailed write-up of the entire process. Check the `example_outputs` for example results produced bu this tool using the `targets`.

![alt text](img/explora.webp)

## Technologies Used

- **Python 3.x**: The primary programming language used to develop the script.
- **OpenAI API**: Used for advanced text analysis and completions.
- **Ghidra**: Assumed for decompilation of binary executables.
- **Standard Python Libraries**:

## Disclaimer

This tool is extremely experimental and may produce errors and bugs. It currently works only on the provided targets. With minor modifications, this tool can be adapted for use with other easy ctf binaries. The generated write-ups are automated and may contain mistakes. Use with caution and verify results manually.

## Setup Instructions

1. **Create and Configure Environment File**

   Add the following `.env` file inside the `explora` directory:

   ```ini
   OPENAI_API_KEY=sk-proj-
   YOUR_ORG_ID=org-
   YOUR_PROJECT_ID=proj_
   MODE=prod
   ```

2. **Set Up Virtual Environment and Install Dependencies**

   ```sh
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r .\requirements.txt
   ```

3. **Run the Script**

   ```sh
   python .\explora\main.py
   ```

4. **Modify Script for Different Binaries**

   If you wish to point to a different binary, modify line 633 in `main.py`:

   ```python
   executable = "./targets/modern2/modern2.exe"
   ```

5. **Output**

   Results will be stored in the `outputs` directory.

## Stages Overview

Explora operates through a multi-stage process:

1. **Stage One**: Initial interaction with the binary, analyzing the outputs.
2. **Stage Two**: Decompilation of the binary using Ghidra, extracting relevant functions.
3. **Stage Three**: Advanced AI analysis of the decompiled code to identify vulnerabilities.
4. **Stage Four**: Fuzzing the binary with AI-generated payloads to find flags.
5. **Stage Five**: Generating a detailed write-up of the entire process.

## Contributions

Contributions are welcome! If you find any bugs or have suggestions for improvements, feel free to submit a pull request.
