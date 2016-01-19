mkdir buddy
gpg --homedir buddy --batch --gen-key buddy.keyconfig

mkdir user1
gpg --homedir user1 --batch --gen-key user1.keyconfig

mkdir user2
gpg --homedir user2 --batch --gen-key user2.keyconfig

# **** need something signed with an expired key
# **** either change your computer time to two days ago for the following commands or wait two days before verifying sig
# mkdir expired
# gpg --homedir expired --batch --gen-key expired.keyconfig
# echo "this will be signed" > to_be_signed
# gpg --homedir expired --output expired.sig --sign to_be_signed
# gpg --homedir expired --armor --export expired@uo.se > expired.asc
# rm to_be_signed
