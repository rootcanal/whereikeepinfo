whereikeepinfo README
==================
Description
-----------

  whereikeep.info is a secure file sharing application. What do we mean by secure? we mean that nothing is stored on the server that could make the contents of your files sharable with the administrators, or anyone else that you do not explicitly authorize for sharing. We do this by using PGP encryption for all of your files.

Basic Workflow
--------------

  First you must register an account to begin the verification process. The first step of the verification process is a simple email will be sent with a verification token that you can use to verify that your registered email account is valid. Next in the verification process of your account, a public and private PGP key pair will be generated for you. You will be prompted for your account passphrase  to generate the encrypted private key. Private Keys are encrypted using AES symmetric block encryption before being stored in the database.

  Once your account has been verified and your keypair has been generated, you will be able to upload files to the server. When uploading files, Your public key will be used by default to encrypt them for storage on the server. If at some later point in time you choose to share the file with another verified user, you will be prompted for your private key passphrase to decrypt the file, then it will be encrypted with yours and the public keys of any verified users you have shared it with.

 When you download a file that you have uploaded, or that has been shared with you by someone else, you will be prompted for your private key passphrase. The file will then be decrypted with your key and you will be able to download it.

NOTE
----

 If you forget your passphrase, you will no longer be able to decrypt any of the files that you have previously uploaded. You should probably delete all those files and then generate a new keypair before uploading anything else.

TODO
-----

 in future releases, the ability to use client generated private keys without ever storing them on the server will be added

Getting Started
---------------

- cd <directory containing this file>

- $VENV/bin/python setup.py develop

- $VENV/bin/initdb development.ini

- $VENV/bin/pserve development.ini

