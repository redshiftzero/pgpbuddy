# pgpbuddy
Baby's first PGP encrypted email buddy! 

# Requirements

    pip install pyyaml python-gnupg

# Configuration

Best is to make a new user for running pgpbuddy. This ensures that buddy will only have access to it's own 
private key and not your keys. 

To extract buddy's key from an existing keyring into it's own clean keyring, run:

    gpg --export-secret-keys -a buddy_keyid > buddy_private_key.asc
    gpg --export -a buddy_keyid > buddy_public_key.asc
    su - pgpbuddy
    gpg --import buddy_private_key.asc
    gpg --import buddy_public_key.asc
    rm buddy_private_key.asc
    rm buddy_public_key.asc

Generate a new config file by runnning

    cp config.default.yaml config.yaml

and in `config.yaml` set your email server parameters and the directory that contains buddy's keyrings.
