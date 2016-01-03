# pgpbuddy
Baby's first PGP encrypted email buddy! 

# Requirements

    pip install pyyaml python-gnupg

# Configuration

    cp config.default.yaml config.yaml
    # and set your email server parameters
    
    # make a keyring that only contains pgpgbuddys key
    # set path/to/new-keyring.gpg in config file
    gpg --keyring pubring.gpg --export BUDDYKEY > /tmp/exported.key
    gpg --no-default-keyring --keyring=buddyring.gpg --import /tmp/exported.key
    $ gpg --export-secret-keys -a keyid > my_private_key.asc
    $ gpg --export -a keyid > my_public_key.asc
