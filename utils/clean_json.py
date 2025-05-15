import json
from pathlib import Path

def clean_json_file(input_path, output_path):
    print(f"Reading from {input_path}")
    print(f"File exists: {input_path.exists()}")
    if not input_path.exists():
        print("File doesn't exist!")
        return False
        
    print(f"File size: {input_path.stat().st_size} bytes")
    
    try:
        # Read line by line
        print("Reading line by line:")
        with open(input_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                print(f"Line {i}: {repr(line[:100])}")
                if i >= 5:  # Just show first 5 lines
                    print("...")
                    break
        
        # Now try to parse the whole thing
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Remove any BOM if present
            if content.startswith('\ufeff'):
                print("Found BOM, removing it")
                content = content[1:]
            # Parse JSON
            data = json.loads(content)
        
        print("Successfully parsed JSON")
        if isinstance(data, list):
            print(f"Found list with {len(data)} items")
        else:
            print(f"Found {type(data)} instead of list")
        
        # Write back with proper formatting
        print(f"Writing to {output_path}")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print("Done!")
        return True
    except UnicodeDecodeError as e:
        print(f"Unicode decode error: {str(e)}")
        return False
    except json.JSONDecodeError as e:
        print(f"JSON decode error at line {e.lineno}, column {e.colno}: {e.msg}")
        print(f"The error occurred at position {e.pos}")
        print(f"The document being parsed was: {e.doc[:100]}...")
        return False
    except Exception as e:
        print(f"Error: {str(e)}")
        print(f"Error type: {type(e)}")
        return False

if __name__ == "__main__":
    input_file = Path("data/Synthetic incident dataset.json")
    output_file = Path("data/incidents.json")
    clean_json_file(input_file, output_file) 