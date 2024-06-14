"""
main.py

Description:
    This program performs a multi-stage process. Each stage is implemented as a separate function,
    and the main function orchestrates the entire process. 

Usage:
    python main.py
"""

import random
import shutil
import subprocess
import logging
import sys
import argparse
import re
import os
import json
from dotenv import load_dotenv
import openai
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Description of the program.")
    parser.add_argument("--option", type=str, help="An optional argument.")
    return parser.parse_args()


class FunctionExtractor:
    """
    A utility class to extract a function containing specific strings from Ghidra code
    and also extract any functions called within those functions.
    """

    def __init__(self, ghidra_code):
        self.ghidra_code = ghidra_code
        self.function_dict = self._parse_functions()

    def extract_functions_containing_strings(self, search_strings):
        """
        Extract the functions from the given code that contain any of the search strings
        and also extract any functions called within those functions.
        """
        unique_functions = set()

        for search_string in search_strings:
            main_function_name, matching_function = self._find_main_function(
                search_string
            )
            if matching_function:
                inner_functions = self._extract_directly_called_functions(
                    matching_function, main_function_name
                )
                unique_functions.add(matching_function)
                unique_functions.update(inner_functions)

        return "\n".join(unique_functions)

    def _parse_functions(self):
        """Parse the Ghidra code into a dictionary of functions."""
        functions = self.ghidra_code.split("/* Function: ")
        function_dict = {
            func.split(" */")[0].strip(): "/* Function: " + func.strip()
            for func in functions
            if " */" in func
        }
        return function_dict

    def _find_main_function(self, search_string):
        """Find the main function containing the search string."""
        for func_name, func_code in self.function_dict.items():
            if search_string in func_code:
                return func_name, func_code
        return None, ""

    def _extract_directly_called_functions(self, func_code, main_function_name):
        """Extract directly called functions within the given function code without further recursion."""
        inner_functions = set()
        called_functions = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", func_code)

        for func_name in called_functions:
            if (
                func_name in self.function_dict
                and func_name not in inner_functions
                and func_name != main_function_name
            ):
                inner_func_code = self.function_dict[func_name]
                inner_functions.add(inner_func_code)

        return inner_functions


def interact_with_binary(executable: str, input_string: str) -> Dict[str, str]:
    """
    Run the specified executable with the given input string and return the output.

    Args:
        executable (str): The path to the executable.
        input_string (str): The input string to send to the executable.

    Returns:
        Dict[str, str]: The output from the executable.
    """
    original_dir = os.getcwd()
    try:
        program_path = os.path.abspath(executable)
        if not os.path.isfile(program_path):
            raise FileNotFoundError(
                f"The program '{executable}' does not exist at '{program_path}'"
            )

        os.chdir(os.path.dirname(program_path))
        process = subprocess.Popen(
            [program_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        stdout, stderr = process.communicate(input=input_string + "\n")
        return {
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
            "returncode": process.returncode,
            "pid": process.pid,
            "args": process.args,
        }
    finally:
        os.chdir(original_dir)


def load_corpus(file_path: str) -> List[Dict[str, str]]:
    """
    Load a text file and convert its lines into a list of JSON objects.

    Args:
        file_path (str): The path to the text file.

    Returns:
        list: A list of dictionaries, each containing a line from the file.
    """
    with open(file_path, "r") as file:
        return [{"line": line.strip()} for line in file]


def save_json(data: Dict, file_path: str):
    """
    Save a dictionary as a JSON file.

    Args:
        data (dict): The data to save.
        file_path (str): The path to the JSON file.
    """
    with open(file_path, "w") as outfile:
        json.dump(data, outfile, indent=4)


def save_text(content: str, file_path: str):
    """
    Save text content to a file.

    Args:
        content (str): The text content to save.
        file_path (str): The path to the text file.
    """
    with open(file_path, "w") as outfile:
        outfile.write(content)


def load_hardcoded_strings(file_path: str) -> List[str]:
    """
    Load hardcoded strings from a JSON file into a list.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        list: A list of hardcoded strings.
    """
    with open(file_path, "r") as file:
        data = json.load(file)
        return data.get("hardcoded_strings", [])


def analyze_interactions(
    results: List[Dict[str, Dict[str, str]]]
) -> Dict[str, List[Dict[str, str]]]:
    """
    Analyze the initial interaction results to provide insights.

    Args:
        results (list): A list of dictionaries containing the input and output.

    Returns:
        dict: A dictionary with analysis results.
    """
    analysis_results = []
    hardcoded_strings = {}

    for idx, result in enumerate(results):
        input_string = result["input"]
        output = result["output"]["stdout"]
        input_length = len(input_string)
        output_length = len(output)
        input_reflected = input_string in output

        output_lines = output.split("\n")
        for line in output_lines:
            if line != input_string and line.strip():
                escaped_line = line.replace("'", "\\'")
                hardcoded_strings[escaped_line] = (
                    hardcoded_strings.get(escaped_line, 0) + 1
                )

        analysis_results.append(
            {
                "id": idx + 1,
                "input": input_string,
                "input_length": input_length,
                "output_length": output_length,
                "input_reflected": input_reflected,
                "stdout": output,
                "stderr": result["output"]["stderr"],
                "returncode": result["output"]["returncode"],
                "pid": result["output"]["pid"],
                "args": result["output"]["args"],
            }
        )

    hardcoded_strings = {k: v for k, v in hardcoded_strings.items() if v > 1}
    flow_map = {string: idx + 1 for idx, string in enumerate(hardcoded_strings.keys())}

    for analysis in analysis_results:
        flow_identifiers = [
            flow_map[line]
            for line in analysis["stdout"].split("\n")
            if line in flow_map
        ]
        analysis["flows"] = list(set(flow_identifiers))

    return {
        "interaction_analyses": analysis_results,
        "hardcoded_strings": list(hardcoded_strings.keys()),
    }


def stage_one(executable: str):
    """First stage of the process."""
    logging.info("Stage One: Starting")

    output_dir = "./outputs"
    os.makedirs(output_dir, exist_ok=True)

    corpus = load_corpus("./inputs/initial_interaction_corpus.txt")
    results = []

    for idx, entry in enumerate(corpus):
        line = entry["line"]
        result = interact_with_binary(executable, line)
        results.append({"id": idx + 1, "input": line, "output": result})

    analysis = analyze_interactions(results)

    save_json(results, os.path.join(output_dir, "initial_interaction_result.json"))
    save_json(analysis, os.path.join(output_dir, "initial_interaction_analysis.json"))

    logging.info("Stage One: Completed")
    return "Stage One Completed"


def decompile_binary(executable_path: str):
    """Mock of the decompiled process, currently performed manually and stored inside the executable_path with the same name ending on .c"""
    logging.info("Decompiling the binary")
    executable_split = executable_path.split("/")
    decompiled_name = executable_split[-1].replace("exe", "c")
    decompiled_path = f"./outputs/{decompiled_name}"
    shutil.copy(executable_path.replace(".exe", ".c"), decompiled_path)
    logging.info(f"binary {executable_path} decompiled to {decompiled_path}")
    return f"./outputs/{decompiled_name}"


def stage_two(executable: str):
    """Second stage of the process, takes the output of stage one as input."""
    logging.info("Stage Two: Starting")

    decompiled_binary_path = decompile_binary(executable)
    hardcoded_strings = load_hardcoded_strings(
        "./outputs/initial_interaction_analysis.json"
    )

    with open(decompiled_binary_path, "r") as file:
        decompiled_code = file.read()

    extractor = FunctionExtractor(decompiled_code)
    results = extractor.extract_functions_containing_strings(hardcoded_strings)
    save_text(results, "./outputs/functions.c")

    logging.info("Stage Two: Completed")
    return "Stage Two Completed"


def load_env():
    """Load environment variables from .env file."""
    load_dotenv()


def initialize_openai_client():
    """Initialize OpenAI client based on environment mode."""
    mode = os.getenv("MODE", "prod")
    if mode == "prod":
        openai.api_key = os.getenv("OPENAI_API_KEY")
        return openai
    return None


def read_file(file_path):
    """Read the contents of a file and return as a string."""
    with open(file_path, "r") as file:
        return file.read()


def read_json(file_path):
    """Read the contents of a JSON file and return as a dictionary."""
    with open(file_path, "r") as file:
        return json.load(file)


def create_chat_completion(prompt, client, mode, response_format=None):
    """Create a chat completion using OpenAI API or return mock response in dev mode."""
    if mode == "dev":
        mock_responses = {
            "initial_interaction_analysis": "This is a mocked response for initial interaction analysis.",
            "decompiled_code_analysis": "This is a mocked response for decompiled code analysis.",
            "suggest_payloads": "This is a mocked response for suggest payloads.",
            "writeup_creation": "This is a mocked response for write-up creation.",
        }
        return mock_responses.get(
            prompt[1]["content"].split()[0], "Mocked response for the prompt."
        )

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=prompt,
        temperature=0,
        max_tokens=1024,
        response_format=response_format,
    )
    return response.choices[0].message.content


def prompt_initial_interaction_analysis(interaction_result):
    """Create prompt for initial interaction analysis."""
    return [
        {
            "role": "system",
            "content": (
                "You are a security analyst. Your task is to analyze the interaction "
                "between a user and a binary using CLI stdin and stdout and provide an "
                "initial interaction analysis. Use the provided interaction data to support your analysis."
            ),
        },
        {
            "role": "user",
            "content": f"The following is an interaction between a user and a binary using CLI stdin and stdout:\n\n```json\n{json.dumps(interaction_result, indent=2)}\n```",
        },
    ]


def prompt_decompiled_code_analysis(decompiled_code):
    """Create prompt for decompiled code analysis."""
    return [
        {
            "role": "system",
            "content": (
                "You are a security analyst. Your task is to analyze the provided Ghidra decompiled code "
                "and offer insights and potential vulnerabilities found in the code."
            ),
        },
        {
            "role": "user",
            "content": f"The following is a Ghidra decompiled code:\n\n```c\n{decompiled_code}\n```",
        },
    ]


def prompt_suggest_payloads(decompiled_code):
    """
    Generates a structured prompt for suggesting potential security payloads based on decompiled code analysis.
    """
    return [
        {
            "role": "system",
            "content": (
                "You are a security analyst. Your task is to create a fuzzing corpus, focusing on how user input "
                "is processed and validated. Use the identified potential vulnerabilities and suggest 5 tokens that could be used to generate "
                "potential payloads by filling the buffer and/or concatenating to exploit these vulnerabilities. Each token should be concise, ideally a short sequence of 1 or 3 chars, and must be distinct from the others. "
                "Additionally, determine the minimum and maximum buffer sizes for the inputs. "
                "List your suggested tokens in a JSON format with the key 'tokens', ensuring no single token suggestion exceeds 100 characters. "
                "Also include 'min_buffer_size' and 'max_buffer_size' keys with their respective values. "
                "Example of expected output format:\n\n"
                "```json\n"
                "{\n"
                '  "min_buffer_size": 39,\n'
                '  "max_buffer_size": 42,\n'
                '  "tokens": [\n'
                '    "token1",\n'
                '    "%p",\n'
                '    "token3",\n'
                '    "z",\n'
                '    "token5"\n'
                "  ],\n"
                "}\n"
                "```"
            ),
        },
        {
            "role": "user",
            "content": f"The following is the analysis of a Ghidra decompiled code:\n\n```c\n{decompiled_code}\n```",
        },
    ]


def prompt_writeup_creation(
    interaction_analysis, decompiled_code, payloads, fuzz_results
):
    """Create prompt for CTF write-up creation."""
    return [
        {
            "role": "system",
            "content": (
                "You are a security analyst. Your task is to create a detailed write-up for a CTF challenge based on the "
                "provided initial interaction analysis, Ghidra decompiled code, payloads, and fuzzing results."
            ),
        },
        {
            "role": "user",
            "content": f"**Initial Interaction Analysis:**\n```json\n{interaction_analysis}\n```",
        },
        {
            "role": "user",
            "content": f"**Ghidra Decompiled Code:**\n```c\n{decompiled_code}\n```",
        },
        {"role": "user", "content": f"**Payloads:**\n```json\n{payloads}\n```"},
        {"role": "user", "content": f"**Fuzz Results:**\n```\n{fuzz_results}\n```"},
    ]


def stage_three(executable: str):
    """Third stage of the process, takes the output of stage two as input."""
    logging.info("Stage Three: Starting")
    load_env()
    client = initialize_openai_client()
    mode = os.getenv("MODE")

    decompiled_code_path = "./outputs/functions.c"
    decompiled_code = read_file(decompiled_code_path)

    decompiled_code_analysis = prompt_decompiled_code_analysis(decompiled_code)
    decompiled_code_analysis_result = create_chat_completion(
        decompiled_code_analysis, client, mode
    )
    print(decompiled_code_analysis_result)

    suggest_payloads_prompt = prompt_suggest_payloads(decompiled_code_analysis_result)
    payloads_result = create_chat_completion(
        suggest_payloads_prompt, client, mode, response_format={"type": "json_object"}
    )
    save_text(payloads_result, "./outputs/payloads.json")

    logging.info("Stage Three: Completed")
    return "Stage Three Completed"


class OutputProcessor:
    @staticmethod
    def flip_endianness(hex_string: str) -> str:
        """Flip the endianness of a given hex string."""
        return "".join(
            reversed([hex_string[i : i + 2] for i in range(0, len(hex_string), 2)])
        )

    @staticmethod
    def convert_to_ascii(hex_string: str) -> str:
        """Convert a hex string to its ASCII representation."""
        try:
            return bytes.fromhex(hex_string).decode("ascii", errors="ignore")
        except ValueError:
            return ""

    @staticmethod
    def extract_flag(ascii_string: str) -> Optional[str]:
        """Extract the flag from the ASCII string."""
        match = re.search(r"flag\{[a-zA-Z0-9_\-]+\}", ascii_string)
        return match.group(0) if match else None


class FlagFinder:
    def __init__(self, processor: OutputProcessor):
        self.processor = processor

    def find_flag_in_output(self, output: Dict[str, str]) -> Optional[str]:
        """Check if the output contains the flag and return it."""
        flag = self.processor.extract_flag(output["stdout"])
        if flag:
            return flag

        hex_values = re.findall(r"[0-9a-fA-F]{16}", output["stdout"])
        hex_string = "".join(hex_values)
        flipped_string = "".join(
            self.processor.flip_endianness(hex_string[i : i + 16])
            for i in range(0, len(hex_string), 16)
        )
        ascii_string = self.processor.convert_to_ascii(flipped_string)

        return self.processor.extract_flag(ascii_string)


class FuzzGenerator:
    def __init__(self, payloads):
        self.payloads = payloads
        self.min_buffer_size = payloads.get("min_buffer_size", 1)
        self.max_buffer_size = payloads.get("max_buffer_size", 1024)
        self.tokens = payloads.get("tokens", [])

    def generate(self):
        buffer_size = random.randint(self.min_buffer_size, self.max_buffer_size)
        token = random.choice(self.tokens)
        return token * buffer_size


class Mutator:
    def __init__(self, tokens):
        self.tokens = tokens

    def mutate(self, input_string):
        token_to_replace = random.choice(self.tokens)
        new_token = random.choice(self.tokens)
        return input_string.replace(token_to_replace, new_token, 1)


class Fuzzer:
    def __init__(self, executable, payloads, flag_finder):
        self.executable = executable
        self.generator = FuzzGenerator(payloads)
        self.mutator = Mutator(payloads.get("tokens", []))
        self.flag_finder = flag_finder

    def fuzz(self) -> Tuple[Optional[str], Optional[str]]:
        while True:
            fuzz_input = self.generator.generate()
            mutated_input = self.mutator.mutate(fuzz_input)
            output = interact_with_binary(self.executable, mutated_input)
            print(mutated_input)
            flag = self.flag_finder.find_flag_in_output(output)
            if flag:
                logging.info(f"Flag found: {flag}")
                return flag, mutated_input


def load_payloads(file_path: str) -> Dict[str, any]:
    """
    Load the payloads from a JSON file.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict: The parsed JSON data as a dictionary.
    """
    with open(file_path, "r") as file:
        return json.load(file)


def stage_four(executable: str) -> Tuple[Optional[str], Optional[str]]:
    """Fourth stage of the process, which involves fuzzing the binary to find the flag."""
    logging.info("Stage Four: Starting")

    payloads = load_payloads("./outputs/payloads.json")
    processor = OutputProcessor()
    flag_finder = FlagFinder(processor)

    fuzzer = Fuzzer(executable, payloads, flag_finder)
    flag, payload = fuzzer.fuzz()

    # Store the payload and flag to the appropriate files
    fuzzing_result = {"flag": flag, "payload": payload}
    save_json(fuzzing_result, "./outputs/fuzzing_flag.json")

    logging.info(f"Stage Four: Flag found - {flag} with payload - {payload}")
    return flag, payload


def stage_five():
    """Fifth stage of the process, generates a complete writeup in markdown."""
    logging.info("Stage Five: Starting")
    load_env()
    client = initialize_openai_client()
    mode = os.getenv("MODE")

    interaction_analysis = read_json("./outputs/initial_interaction_analysis.json")
    decompiled_code = read_file("./outputs/functions.c")
    payloads = read_json("./outputs/payloads.json")
    fuzz_results = {
        "flag": read_json("./outputs/fuzzing_flag.json")["flag"],
        "payload": read_json("./outputs/fuzzing_flag.json")["payload"],
    }

    writeup_prompt = prompt_writeup_creation(
        interaction_analysis, decompiled_code, payloads, fuzz_results
    )
    writeup_result = create_chat_completion(writeup_prompt, client, mode)

    save_text(writeup_result, "./outputs/final_writeup.md")

    logging.info("Stage Five: Completed")
    return "Stage Five Completed"


def main():
    """Main function to orchestrate the stages."""
    logging.info("Program Started")

    executable = "./targets/modern3/modern3.exe"

    # Parse command line arguments
    args = parse_arguments()

    try:
        # Execute stages
        result_stage_one = stage_one(executable)
        result_stage_two = stage_two(executable)
        result_stage_three = stage_three(executable)
        flag, payload = stage_four(executable)
        result_stage_five = stage_five()

        logging.info(f"Payoad Result: {payload}")
        logging.info(f"Flag Result: {flag}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    logging.info("Program Finished Successfully")


if __name__ == "__main__":
    main()
