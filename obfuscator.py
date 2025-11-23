import random
import zlib
import base64
import marshal
import sys
from types import CodeType

def random_name(length=8):
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_') for _ in range(length))

def obfuscate_code(source_code):
    # Сжимаем код
    compressed = zlib.compress(source_code.encode())
    
    # Кодируем в base64
    encoded = base64.b64encode(compressed)
    
    # Создаем случайные имена для переменных
    var_names = [random_name() for _ in range(10)]
    
    # Генерируем обфусцированный код
    obfuscated = f"""
import zlib, base64, marshal
{var_names[0]} = {encoded}
{var_names[1]} = base64.b64decode({var_names[0]})
{var_names[2]} = zlib.decompress({var_names[1]})
{var_names[3]} = compile({var_names[2]}, '<obfuscated>', 'exec')
exec({var_names[3]})
"""
    
    return obfuscated

def deep_obfuscate(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    # Первый уровень обфускации
    obfuscated = obfuscate_code(code)
    
    # Второй уровень - кодирование marshal
    compiled = compile(obfuscated, '<string>', 'exec')
    marshaled = marshal.dumps(compiled)
    
    # Генерация финального кода
    final_code = f"""
import marshal
exec(marshal.loads({marshaled}))
"""
    
    return final_code

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python obfuscator.py <input_file.py>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = input_file.replace('.py', '_obfuscated.py')
    
    obfuscated = deep_obfuscate(input_file)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(obfuscated)
    
    print(f"Obfuscated code saved to {output_file}")