import os
import sys
import google.generativeai as genai
from pathlib import Path
from dotenv import load_dotenv


def read_input_file(file_path: str) -> str:
    """Read and return the contents of a file.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        The contents of the file as a string
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If there's an error reading the file
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


def query_llm(query: str, file_content: str) -> str:
    """Send a query to the LLM with file contents.
    
    Args:
        query: The question or instruction for the LLM
        file_content: The content to provide context to the LLM
        
    Returns:
        The LLM's response as a string
        
    Raises:
        ValueError: If GEMINI_API_KEY is not found
        Exception: If the API call fails
    """
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in environment variables.")
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-3-flash-preview')
    prompt = f"{query}\n\nFile contents:\n{file_content}"
    
    response = model.generate_content(prompt)
    return response.text


def save_output(content: str, output_path: str) -> None:
    """Save content to a file.
    
    Args:
        content: The content to save
        output_path: Path where to save the file
        
    Raises:
        IOError: If there's an error writing the file
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)


def process_file(template_path: str, logs_path: str, query: str, output_path: str = None) -> str:
    template_content = read_input_file(template_path)
    logs_content = read_input_file(logs_path)
    # Combine both contents for the LLM prompt
    combined_content = f"TEMPLATE FILE:\n{template_content}\n\nLOGS FILE:\n{logs_content}"
    response = query_llm(query, combined_content)
    
    if output_path:
        save_output(response, output_path)
    
    return response


def main():
    """CLI entry point."""
    if len(sys.argv) < 4:
        print("Usage: python main.py <template> <logs> <query> [output_file]")
        print("Example: python main.py template.txt logs.txt 'Summarize this file' output.txt")
        sys.exit(1)
    
    template_file = sys.argv[1]
    logs_file = sys.argv[2]
    query = sys.argv[3]
    output_file = sys.argv[4] if len(sys.argv) > 4 else "llm_output.txt"
    
    try:
        # Read input file
        print(f"Reading file: {template_file}  and {logs_file}")
        response = process_file(template_file, logs_file, query, output_file)
        
        # Print success message
        print(f"Output saved to: {output_file}")
        
        # Print output
        print("\n" + "="*50)
        print("LLM Response:")
        print("="*50)
        print(response)
        print("="*50)
        
    except FileNotFoundError:
        print(f"Error: File '{template_file}' or '{logs_file}' not found")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        print("Please create a .env file with: GEMINI_API_KEY=your-api-key")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
