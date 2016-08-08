# webpass 
A secure web-based password manager.

## What does webpass do?
webpass encrypts passwords and saves them to disk, allowing only authenticated users to view them, or even know of their existence.

## How does webpass save my passwords?
### Login
To make sure that the server knows who you are, you must log in first. Don't worry, webpass uses HTTPS connections, so your login is safe.

1. Visit the website of the server where your passwords are stored.
2. Log in, using your GPG key user ID and GPG private key passphrase. Your passphrase is never written to disk.
3. Once your GPG private key is unlocked in memory, you may begin to read and write your passwords. Your unlocked GPG private key is never written to disk.

### Password Protection
When you save a password through a webpass page, a few things happen:

1. The password passes through the NodeJS backend, never written to disk.
2. The password is then encrypted from memory by the user's GPG public key.
3. This encrypted GPG message is then saved inside the password store, inside a subdirectory specified by the user.

### Password Viewing
When you view your password, you begin a decryption sequence.

1. First, the now unlocked GPG private key of yours is used to decrypt your target password.
2. Then, the password is sent to you over the secured HTTPS websocket connection.

## How do I install webpass on a server?
1. Download this repository.
2. On Debian-based systems, simply use ./INSTALL while inside the repository.
   - If you do not use Debian, it should be a simple port to whatever system you use. Just change the `apt-get` line to your package manager.
3. Change the fields listed by the installer for your customization preferences.
4. Run the command: `sudo node webpass.js`.

## How do I install webpass on a client?
You don't. All you need to do is visit the webpage of a server running webpass.

## Can I contribute code?
Sure! Just make any changes you feel would improve webpass and make a pull request. I'll review it and pull if everything checks out.

