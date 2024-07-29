# Define the API functions for each DLL
WindowsAPI = {
    "Kernel32": [
        "FindResourceA", "LoadResource", "SizeofResource", "LockResource",
        "CreateFileA", "WriteFile", "Sleep", "GetModuleFileNameA",
        "GetTempPathA", "CloseHandle", "ExitProcess", "VirtualProtect",
        "CreateThread", "VirtualAlloc", "LoadLibraryA", "WaitForSingleObject",
        "GetCommandLineA", "GetFileAttributesA","HeapAlloc","GetProcessHeap"
    ],
    "Ntdll": [
        "RtlMoveMemory"
    ],
    "Wininet": [
        "InternetOpenA", "InternetOpenUrlA", "HttpQueryInfoA",
        "InternetReadFile", "InternetCloseHandle"
    ],
    "User32": [
        "MessageBoxA", "MessageBoxW",
    ],
    "Shell32": [
        "ShellExecuteA", "SHGetFolderPathA"
    ]
}

# Helper functions
def define_hashes(dll_name, functions):
    hashes = [f"    constexpr auto {name}Hash = Hash(\"{name}\");" for name in functions]
    return "\n".join(hashes)

def define_macros(dll_name, functions):
    macro_name = f"{dll_name}Hashes"
    formatted_functions = ",\\\n".join(f"\t{name}Hash" for name in functions)
    return f"#define {macro_name} {{ \\\n{formatted_functions} \\\n}}"

def define_pointers(dll_name, functions, index):
    lines = []
    for i, func in enumerate(functions):
        func_name = f"p{func}"
        lines.append(f"#define {func_name} (({func}Func)functions[{index}][{i}])")
    return "\n".join(lines)

def define_dll_names(dll_dict):
    dll_definitions = []
    for dll_name in dll_dict.keys():
        char_array = ", ".join(f"'{char}'" for char in dll_name + '.dll') + ", '\\0'"
        dll_definitions.append(f"#define {dll_name} {{ {char_array} }}")
    return "\n".join(dll_definitions)

def define_dll_macro(dll_dict):
    macros = []
    for i, dll_name in enumerate(dll_dict.keys()):
        macro_name = f"sz{dll_name}"
        hash_macro = f"{dll_name}Hashes"
        macros.append(f"    {{ (char*){macro_name}, {hash_macro}, sizeof({hash_macro}) / sizeof({hash_macro}[0]) }}")
    return "#define DLL {\n" + ",\n".join(macros) + "}"

def define_dll_macro(dll_dict):
    dll_macro_lines = []
    for dll_name in dll_dict.keys():
        # Convert first letter to lowercase
        lower_dll_name = dll_name[0].lower() + dll_name[1:]
        dll_macro_lines.append(f"    {{ (char*)sz{dll_name}, {lower_dll_name}Hashes, sizeof({lower_dll_name}Hashes) / sizeof({lower_dll_name}Hashes[0]) }}")
    return "#define DLL \\\n" + ", \\\n".join(dll_macro_lines)

# Generating content
output = []

# Add pragma once
output.append("#pragma once")

# Add Hash function definition
output.append("""// Hash function definition
constexpr DWORD Hash(const char* functionName) {
    DWORD hash = 0;
    while (*functionName) {
        hash = (hash * 138) + *functionName;
        functionName++;
    }
    return hash;
}
""")

# Define DLL names
output.append("// Define DLL names")
output.append(define_dll_names(WindowsAPI))

# Generate hash definitions
output.append("")  # Adding a blank line for separation
output.append("// Define Hashes")
for dll_name, functions in WindowsAPI.items():
    output.append(define_hashes(dll_name, functions))

# Generate macros
output.append("")  # Adding a blank line for separation
output.append("// Define Hash Arrays")
dll_names = list(WindowsAPI.keys())
for index, dll_name in enumerate(dll_names):
    functions = WindowsAPI[dll_name]
    output.append(define_macros(dll_name, functions))

# Generate DLL macro
output.append("")  # Adding a blank line for separation
output.append("// Define DLL Macro")
output.append(define_dll_macro(WindowsAPI))

# Generate function pointers
output.append("")  # Adding a blank line for separation
for index, (dll_name, functions) in enumerate(WindowsAPI.items()):
    output.append(f"// {dll_name}.dll")
    output.append(define_pointers(dll_name, functions, index))
    output.append("")  # Adding a blank line for separation

# Output to file
with open('..\\include\\hash.h', 'w') as file:
    file.write("\n".join(output))

print("Header file 'hash.h' has been generated.")
