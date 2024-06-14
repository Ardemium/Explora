*AI generated*

## CTF Challenge Write-Up: "What's the Secret?"

### Challenge Overview
In this challenge, participants are tasked with exploiting a vulnerable binary to retrieve a hidden flag. The binary prompts the user for a secret and performs a series of checks before printing the input back to the user. The goal is to bypass these checks and leverage a format string vulnerability to extract the flag.

### Initial Interaction Analysis
The initial interaction analysis provides insight into how the binary behaves with different inputs:

1. **Empty Input:**
   - **Input:** `""`
   - **Output:** `"What's the secret ?\n\n\nSee u soon!"`
   - **Return Code:** `0`
   - **Behavior:** The program prompts for a secret and exits normally.

2. **Valid Input:**
   - **Input:** `"Hello, World!"`
   - **Output:** `"What's the secret ?\nHello, World!\n\nSee u soon!"`
   - **Return Code:** `0`
   - **Behavior:** The program echoes the input and exits normally.

3. **Invalid Input:**
   - **Input:** `"Input"`
   - **Output:** `"What's the secret ?\nNOT ALLOWED!"`
   - **Return Code:** `1`
   - **Behavior:** The program rejects the input and exits with an error.

4. **Invalid Input:**
   - **Input:** `"Test"`
   - **Output:** `"What's the secret ?\nNOT ALLOWED!"`
   - **Return Code:** `1`
   - **Behavior:** The program rejects the input and exits with an error.

5. **Invalid Input:**
   - **Input:** `"stdin"`
   - **Output:** `"What's the secret ?\nNOT ALLOWED!"`
   - **Return Code:** `1`
   - **Behavior:** The program rejects the input and exits with an error.

### Ghidra Decompiled Code Analysis
The decompiled code reveals the internal workings of the binary:

- **Main Function:**
  - Opens `flag.txt` and reads its content.
  - Prompts the user with `"What's the secret ?"`
  - Reads up to 100 characters of input.
  - Performs a `sanity_check` on the input.
  - Prints the input using `printf`.
  - Prints `"See u soon!"` and exits.

- **Sanity Check Function:**
  - Checks if the input contains any of the characters: `s`, `x`, `n`, `S`, `X`, `N`.
  - If any of these characters are found, it prints `"NOT ALLOWED!"` and exits with an error.

### Payloads
The payloads used for fuzzing include various format string specifiers:
- `%n`
- `%x`
- `%s`
- `%p`
- `%%`

### Fuzz Results
The fuzzing results indicate that a specific payload successfully retrieved the flag:
- **Payload:** `%%%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p`
- **Flag:** `flag{a7cv8er5cvnb5f97z7evs54dsg}`

### Exploitation Steps
1. **Understanding the Vulnerability:**
   - The binary uses `printf` to print user input without proper sanitization, leading to a format string vulnerability.

2. **Crafting the Payload:**
   - The payload leverages the `%p` specifier to read memory addresses from the stack.

3. **Executing the Exploit:**
   - By providing the crafted payload, the binary prints out memory addresses, eventually revealing the flag.

### Conclusion
This challenge demonstrates the exploitation of a format string vulnerability to retrieve a hidden flag. Participants must understand the binary's behavior, identify the vulnerability, and craft a suitable payload to extract the flag.

### Flag
`flag{a7cv8er5cvnb5f97z7evs54dsg}`

### Notes
- Ensure to sanitize user inputs to prevent format string vulnerabilities.
- Always validate and restrict user inputs to avoid unintended behavior and potential security risks.