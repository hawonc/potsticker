# AI Module

Python module for querying LLMs (Gemini) with file contents.

## Installation

From another project, you can import this module:

```bash
# Add the ai directory to your Python path or install as package
pip install -e /path/to/potsticker/ai
```

## Usage as a Module

```python
from ai import process_file

# Simple usage
response = process_file(
    file_path="data.txt",
    query="Summarize this file",
    output_path="output.txt"  # Optional
)
print(response)
```

## Usage as CLI

```bash
python main.py <input_file> <query> [output_file]
```

Example:
```bash
export GEMINI_API_KEY="your-key"
python main.py data.txt "Summarize this file" output.txt
```

## API Reference

### `process_file(file_path, query, output_path=None)`

High-level function that reads a file, queries the LLM, and optionally saves the output.

- **file_path**: Path to the input file
- **query**: Question or instruction for the LLM
- **output_path**: Optional path to save the response

Returns the LLM's response as a string.

### `query_llm(query, file_content)`

Send a query to the LLM with provided content.

### `read_input_file(file_path)`

Read and return file contents.

### `save_output(content, output_path)`

Save content to a file.
