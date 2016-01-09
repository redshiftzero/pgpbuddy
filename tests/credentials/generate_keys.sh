mkdir buddy
gpg --homedir buddy --batch --gen-key buddy.keyconfig

mkdir user1
gpg --homedir user1 --batch --gen-key user1.keyconfig

mkdir user2
gpg --homedir user2 --batch --gen-key user2.keyconfig