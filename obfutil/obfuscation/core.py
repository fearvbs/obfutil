import ast, astor, base64, os, random, string, hashlib, zlib, textwrap

def _r(n=12):
    """Generate random string"""
    return ''.join(random.choice(string.ascii_letters) for _ in range(n))

def _xor(s, key):
    """XOR encryption"""
    return bytes([c ^ key for c in s])

def _enc_b64(b):
    """Base64 encode"""
    return base64.b64encode(b).decode()

def _dec_b64(s):
    """Base64 decode"""
    return base64.b64decode(s)

def encrypt_string(s: str):
    """Encrypt string with XOR and base64"""
    key = random.randint(1, 255)
    enc = _enc_b64(_xor(s.encode(), key))
    return enc, key

DECODE_STUB = """
import base64
def __SDEC(e, k):
    b = base64.b64decode(e)
    return ''.join(chr(c ^ k) for c in b)
"""

class NuclearObfuscator(ast.NodeTransformer):
    """AST node transformer for code obfuscation"""
    def __init__(self):
        self.vmap = {}

    def visit_Name(self, node):
        """Obfuscate variable names"""
        if isinstance(node.ctx, (ast.Load, ast.Store)):
            if node.id not in self.vmap:
                self.vmap[node.id] = _r(15)
            node.id = self.vmap[node.id]
        return node

    def visit_Constant(self, node):
        """Obfuscate string constants"""
        if isinstance(node.value, str):
            e, k = encrypt_string(node.value)
            return ast.Call(
                func=ast.Name("__SDEC", ast.Load()),
                args=[ast.Constant(e), ast.Constant(k)],
                keywords=[]
            )
        return node

    def visit_JoinedStr(self, node):
        """Obfuscate f-string components"""
        new = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                e, k = encrypt_string(v.value)
                call = ast.Call(
                    func=ast.Name("__SDEC", ast.Load()),
                    args=[ast.Constant(e), ast.Constant(k)],
                    keywords=[]
                )
                new.append(ast.FormattedValue(call, -1))
            else:
                new.append(v)
        node.values = new
        return node

def shred_code(code: str):
    """Shuffle code lines"""
    lines = [l+"\n" for l in code.splitlines()]
    random.shuffle(lines)
    return lines

def wrap_runtime_engine(chunks):
    """
    Assemble code on the fly from shuffled fragments
    using pseudo-random execution order
    """

    tbl_name = _r(12)
    exec_name = _r(12)
    key_name = _r(12)
    order_name = _r(12)

    mapping = {}
    for i, ch in enumerate(chunks):
        s = ch
        key = random.randint(1, 255)
        encoded = _enc_b64(_xor(s.encode(), key))
        mapping[_r(10)] = (encoded, key)

    tbl_items = []
    for k, (enc, key) in mapping.items():
        tbl_items.append(f'"{k}": ("{enc}", {key})')

    # Pseudo-random execution order
    keys = list(mapping.keys())
    random.shuffle(keys)
    order_list = ", ".join([f'"{k}"' for k in keys])

    return f"""
import base64, random, sys

{tbl_name} = {{
    {','.join(tbl_items)}
}}

{order_name} = [{order_list}]

def {exec_name}():
    src = ""
    for k in {order_name}:
        enc, kk = {tbl_name}[k]
        part = "".join(chr(c ^ kk) for c in base64.b64decode(enc))
        src += part
    exec(src, globals(), globals())

{exec_name}()
"""

def obfuscate_code(source: str) -> str:
    """Main obfuscation function"""
    # === STEP 1: parse ===
    tree = ast.parse(source)

    # === STEP 2: add decoder ===
    dec_ast = ast.parse(DECODE_STUB).body
    tree.body = dec_ast + tree.body

    # === STEP 3: AST obfuscation ===
    tree = NuclearObfuscator().visit(tree)
    ast.fix_missing_locations(tree)

    # === STEP 4: convert to source ===
    obf_source = astor.to_source(tree)

    # === STEP 5: shred real code ===
    pieces = shred_code(obf_source)

    # === STEP 6: pack into runtime engine ===
    final_payload = wrap_runtime_engine(pieces)

    # === STEP 7: add anti-tamper ===
    chk = hashlib.sha256(final_payload.encode()).hexdigest()
    verify = f"""
import hashlib, sys
__c = "{chk}"
try:
    d = open(__file__, "rb").read().decode(errors="ignore")
    if hashlib.sha256(d.encode()).hexdigest() != __c:
        raise SystemExit("CORRUPT")
except:
    pass
"""

    # === STEP 8: stuff with huge junk ===
    junk = "\n".join(
        f"def { _r(20) }(): return {random.randint(1,999999)}"
        for _ in range(700)
    )

    return verify + "\n" + junk + "\n" + final_payload