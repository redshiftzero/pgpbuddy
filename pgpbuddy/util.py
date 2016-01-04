

# python can not directly do lookup of enums -> replace enums in the dictionary keys with their integer representations
def compile_lookup_table(lookup_table):
    return {tuple([key.value for key in keys]): message for keys, message in lookup_table.items()}