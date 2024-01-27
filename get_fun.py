import re

def extract_functions(file_content):
 
    function_pattern = re.compile(r'^\s*\w+\s+\*?(\w+)\s*\([^)]*\)\s*\{', re.MULTILINE)
    
    matches = function_pattern.findall(file_content)
    return matches

file_path = 'path_to_your_source_file.c' # File path goes here
with open(file_path, 'r') as file:
    content = file.read()

function_list = extract_functions(content)
for function in function_list:
    print(f'fun: {function}')
