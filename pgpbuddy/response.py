from pgpbuddy.crypto import Signature, Encryption

# python can not directly do lookup of enums -> replace enums in the dictionary keys with their integer representations
def compile_lookup_table(lookup_table):
    return {tuple([key.value for key in keys]): message for keys, message in lookup_table.items()}

subject = {(Encryption.correct, Signature.correct):
           'PGP email successfully signed and encrypted!',

           ( Encryption.correct, Signature.missing):
           'PGP email successfully encrypted! (not signed)',

           (Encryption.missing, Signature.correct):
           'PGP email successfully signed! (not encrypted)',

           (Encryption.incorrect, Signature.missing):
           'I could not decrypt your PGP mail',

           # (Encryption.incorrect, Signature.correct): this case can not happen because pgp can't check the sig

           (Encryption.incorrect, Signature.correct):
           'I could not decrypt your PGP mail (signed)',

           (Encryption.missing, Signature.missing):
           'Unencrypted, unsigned email detected'}


content = {(Encryption.correct, Signature.correct):
           'You\'ve correctly signed and encrypted an email to me!',

           (Encryption.correct, Signature.missing):
           'You\'ve correctly encrypted an email to me!',

           (Encryption.incorrect, Signature.missing):
           'You sent me an encrypted mail, but I could not decrypt it',

           # (Encryption.incorrect, Signature.correct): this case can not happen because pgp can't check the sig

           (Encryption.missing, Signature.correct):
           'You\'ve correctly signed an email to me!',

           (Encryption.missing, Signature.missing):
           ('Welcome to PGPBuddy! It looks like you\'ve sent plaintext '
            '(clear, unencrypted text).\n\n'
            'To get started, set up PGP using one of these tutorials from '
            'the Electronic Frontier Foundation: \n\n'
            'Windows: https://ssd.eff.org/en/module/how-use-pgp-windows\n'
            'Mac OS X: https://ssd.eff.org/en/module/how-use-pgp-mac-os-x\n'
            'Linux: https://ssd.eff.org/en/module/how-use-pgp-linux\n\n'
            'Once you have your key ready, send me an encrypted and/or signed '
            'email and I\'ll check things are working!')}

default_subject = "Buddy does not understand you"
default_content = "Had trouble parsing your message. sorry. good luck."

content = compile_lookup_table(content)
subject = compile_lookup_table(subject)

