/**
 * webpass.js
 *
 * Program objectives:
 *   - Create a dynamic, secure, and (somewhat) user-friendly web interface for password storage, search, and recovery.
 *
 * Features:
 *   - Password storage as secured by gpg/pgp encryption.
 *     - Passwords may be altered by authorized users.
 *     - Subdirectories and passwords may be created by any end user.
 *     - Passwords may be marked as readable by multiple users.
 *   - Backups through localized git.
 *   - Low end user performance.
 *     - Usable on most modern browsers.
 *     - Minimal page size (see: index.html).
 *     - Encryption/decryption performed serverside.
 *   - Exploitation prevention.
 *     - Strict regular expression checks against all shell- and webpage-inserted strings.
 *     - No disclosure of private gpg keys.
 *     - No stack traces/logs published to end user.
 *
 */

/**
 * Declare all required scripts for later usage.
 *
 * https:
 *   - Used to create the HTTPS connection.
 *   - No data will pass through an unsecured connection (including websocket data).
 *
 * fs:
 *   - Used for several reasons:
 *     - Collects the public and private SSL/TLS keys for HTTPS connection.
 *     - Collects the armored message files for password extraction.
 *     - Verifying the existence of keys which the user may not overwrite (invisible on client side).
 *
 * express:
 *   - Used to set up the server listening on port 443.
 *
 * openpgp:
 *   - Used for most gpg-related scripting, specifically:
 *     - Unlocking the private keys.
 *       - Using opengpg.js for unlocking prevents keys from being unlocked for other connections.
 *     - Parsing and decrypting the passwords.
 *
 * child_process:
 *   - Used for shell access.
 *     - This will call shell-based gpg to:
 *       - Export armored and locked private keys for use by openpgp.js.
 *       - Armor keys for future use.
 *     - This will call ./gpgfind to:
 *       - Locate the passwords currently available in ~/.password_store/
 *       - Assign authorized users to various passwords.
 *
 */

const https = require('https'),
  fs = require('fs'),
  socketIO = require('socket.io'),
  express = require('express'),
  openpgp = require('./openpgp.js'),
  child_process = require('child_process');

/**
 * Define all constants that may or may not be altered by the administrator.
 *
 * privKey (string):
 *   - HTTPS SSL/TLS private key.
 *   - The administrator should place a private key in the webpass directory called 'key.pem'.
 *
 * cert (string):
 *   - HTTPS SSL/TLS public certificate.
 *   - The administrator should place a public cert in the webpass directory called 'cert.pem'.
 *
 * keyPassphrase (string):
 *   - HTTPS SSL/TLS private key passphrase.
 *   - If you have no passphrase, set this to ''.
 *
 * htmlPageSent (string):
 *   - The webpage that is sent to the end user. This is the web interface.
 *
 * passdir (string):
 *   - The main directory in which the passwords have been stored.
 *
 * port (int):
 *   - This is the port that the server will listen to.
 *
 * usercheck (regex):
 *   - The regular expression used to check against usernames.
 *   - Altering this to an unsafe regular expression may allow for code injection!
 *
 * filecheck (regex):
 *   - The regular expression used to check against filenames.
 *   - Altering this to an unsafe regular expression may allow for code injection!
 *
 * foldcheck (regex):
 *   - The regular expression used to check against folder names.
 *   - Altering this to an unsafe regular expression may allow for code injection!
 *
 */

const privKey = fs.readFileSync('key.pem').toString(),
  cert = fs.readFileSync('cert.pem').toString(),
  keyPassphrase = '',
  htmlPageSent = '/webpass.html',
  passdir = process.env.HOME + '/.password-store/',
  port = 443,
  usercheck = /^[a-zA-Z0-9_\.\s]+$/,
  filecheck = /^[a-zA-Z0-9_\s\/\.]+\.gpg$/,
  foldcheck = /^[a-zA-Z0-9_\s\/\.]+$/;

/**
 *
 * Build the main express object.
 *
 */

var app = express();

/**
 *
 * Verificiation function.
 *
 * Function objectives:
 *   - Verify that a user has a key on the server.
 *   - Once verified:
 *     - Send the user their accessible key tree.
 *     - Open new websocket listeners for the user's specific socket.
 *
 */

var verify = function(name, pass, socket) {
  /**
   *
   * Main try block.
   *  - If the user causes any fatal errors:
   *    - Catch the error.
   *    - Log the stacktrace.
   *    - Inform the user that encryption/decryption failed.
   *    - Reopen all affected connections.
   *
   */
  try {

    /**
     *
     * Address through which all communications occur. This value is stored for logging purposes.
     *
     */
    var address = socket.handshake.address;

    console.log('User ' + name + ' (' + address.address + ':' + address.port + ' attempted to unlock their key.');

    /**
     *
     * Define the GPG private key for the user.
     *
     */
    var gpgPrivKey = openpgp.key.readArmored(execSync(
      'gpg --armor --export-secret-key "' + name + '"'), false).keys[0];

    // Verify that key exists.
    if (gpgPrivKey == undefined) {
      console.log('No GPG key found for user ' + name + ' (' + address.address + ':' + address.port + ').');
      socket.emit('updateOut', 'GPG key not found.');
      return;
    }

    // Verify that the given passphrase unlocks the user's private key.
    if (!gpgPrivKey.decrypt(pass)) {
      socket.emit('updateOut', 'Invalid passphrase.');
      console.log('User ' + name + ' (' + address.address + ':' + address.port + ') failed to provide a valid passphrase.');
      return;
    }

    socket.emit('updateOut', 'Validated.');

    // Define all verified passwords and also send the tree to the user.
    var verifiedPasswords = sendTree(name, socket);

    // Define future functions, but don't give them values yet.
    var getPass,
      makePass,
      makeFold;

    /**
     *
     * getPass function.
     *
     * Function objectives:
     *   - Retrieve a password for the user.
     *     - Password will be verified (if their key cannot decrypt the message, it will not be sent).
     *     - Password will be sanitized (prevent code injection).
     *   -
     *
     */
    getPass = function(passname) {
      console.log('User ' + name + ' (' + address.address + ':' + address.port + ') queried for password ' + passname);
      if (!filecheck.test(passname)) {
        socket.emit('updateOut', 'Bad character in query.');
        return;
      }

      socket.removeAllListeners('retrievePass');

      passname = passdir + passname.substring(2);

      try {
        exec('gpg --enarmor --yes ' + passname, false, function(e, so, se) {
          var options = {
            message: openpgp.message.readArmored(getFileString(
              passname + '.asc').split('ARMORED FILE').join(
              'MESSAGE')),
            privateKey: gpgPrivKey
          };

          console.log('Options built and validated for user ' + name +
            ' (' + address.address + ':' + address.port + ').');

          openpgp.decrypt(options).then(function(plaintext) {
            console.log('Decryption succeeded for user ' + name +
              ' (' + address.address + ':' + address.port + ').');
            socket.emit('updateOut', 'Password ' + passname.split(
                '/').pop() +
              ' unlocked: ' + plaintext.data);
            console.log('Sent password for user ' + name + ' (' + address.address + ':' + address.port + ').');
            socket.on('retrievePass', getPass);
          });
        });
      } catch (exc) {
        socket.emit('updateOut', 'Invalid target.');
        console.log('User ' + name + ' (' + address.address + ':' + address.port + ') failed to provide a valid target.');
        socket.removeAllListeners('retrievePass');
        socket.on('retrievePass', getPass);
        return;
      }
    }

    socket.on('retrievePass', getPass);

    makePass = function(passdetails) {

      socket.removeAllListeners('makePass');

      var passpath = passdetails.newpassname,
        password = passdetails.newpassword,
        recipients = passdetails.recipients;

      if (!filecheck.test(passpath)) {
        socket.emit('updateOut', 'Bad password path.');
        socket.on('makePass', makePass);
        return;
      }


      try {
        fs.accessSync(passdir + passpath, fs.F_OK);
        if (verifiedPasswords.indexOf(passpath.substring(2)) == -1) {
          console.log('User ' + name + ' (' + address.address + ':' + address.port + ') attempted to overwrite password ' +
            passpath + '.');
          socket.emit('updateOut', 'Cannot overwrite key (auth).');
          socket.on('makePass', makePass);
          return;
        }
      } catch (exc) {}

      password = password.split("'").join("\'\"\'\"\'");

      recipstr = "";

      for (ind = 0; ind < recipients.length; ind++) {
        console.log('User ' + name + ' attempted to add recipient ' +
          recipients[ind] + ' to password ' + passpath + '.');
        if (usercheck.test(recipients[ind])) {
          socket.emit('updateOut', 'Invalid username: ' + recipients[ind]);
          socket.on('makePass', makePass);
          return;
        } else if (execSync('gpg --armor --export-secret-key "' +
            recipients[ind] + '"').valueOf() == '') {
          socket.emit('updateOut', 'Recipient ' + recipients[ind] +
            ' does not exist.');
          socket.on('makePass', makePass);
          return;
        }
        recipstr += ' -r ' + recipients[ind];
      }

      try {
        exec("echo '" + password + "' | gpg -e" + recipstr +
          " --always-trust --yes --batch -o " + passdir + passpath, true,
          function(e, stdout, stderr) {
            if (stderr == undefined) {
              return;
            }
            if (err) {
              throw err;
            }
            if (stderr.indexOf('encryption failed') != -1) {
              if (stderr.indexOf('public key not found') != -1) {
                var lines = stderr.split('\n');
                for (ind = 0; ind < lines.length; ind++) {
                  if (lines[ind].indexOf('public key not found') != -1) {
                    var failedUser = lines[ind].substring(5);
                    failedUser = failedUser.substring(0, failedUser.indexOf(
                      ':'));
                    socket.emit('updateOut', 'No key for user: ' +
                      failedUser);
                    socket.on('makePass', makePass);
                    return;
                  }
                }
              }
              throw new Error();
            }
          });
      } catch (exc) {
        socket.emit('updateOut', 'Encryption error.');
        socket.on('makePass', makePass);
        return;
      }

      socket.emit('updateOut', 'Password ' + passpath.split('/').pop() +
        ' saved.');
      socket.emit('editSuccess', null);
      var gitupdate = execSync("cd " + passdir +
        "; git add -A; git commit -m 'User " + name +
        " updated password " + passpath + ".'", false).toString();
      console.log('git updated: ' + gitupdate);
      socket.on('makePass', makePass);
    }

    socket.on('makePass', makePass);

    makeFold = function(foldname) {

      socket.removeAllListeners('makeFold');

      if (!foldcheck.test(foldname)) {
        socket.emit('updateOut', 'Bad folder name.');
        socket.on('makeFold', makeFold);
        return;
      }

      try {
        exec("mkdir -p " + passdir + foldname, false, function(err, stdout,
          stderr) {
          if (stderr == undefined) {
            return;
          }
          throw new Error();
        });
      } catch (exc) {
        socket.emit('updateOut', 'Folder creation error.');
        socket.on('makeFold', makeFold);
        return;
      }

      console.log('User '+name+' (' + address.address + ':' + address.port + ') made directory '+foldname);
      socket.emit('updateOut', 'Subdirectory ' + foldname +
        ' made successfully.');
      socket.emit('editSuccess', null);
      socket.on('makeFold', makeFold);

    }

    socket.on('makeFold', makeFold);

  } catch (exc) {
    console.log('User ' + name + ' (' + address.address + ':' + address.port + ') caused an unhandled error.');
    console.log('Stack trace:');
    console.log(exc.stack);
    socket.emit('updateOut', 'Unknown error.');
  }
}

var sendTree = function(name, socket) {
  var verifiedPasswords = [];
  exec('bash gpgfind "' + passdir + '"', false, function(stdout, stderr) {
    var passwords = stdout.split('\n'),
      ownersToCheck = stderr.split('\n');

    passwords.pop();
    var passind = 0;

    for (ind = 0; ind < ownersToCheck.length; ind += 1) {
      if (ownersToCheck[ind].indexOf(
          'gpg: decryption failed: secret key not available') != -1) {
        passind += 1;
      } else if (~ownersToCheck[ind].indexOf(name)) {
        verifiedPasswords.push(passwords[passind].substring(passdir.length));
        console.log('User ' + name +
          ' (' + address.address + ':' + address.port + ') was marked as authorized for password ' + passwords[passind]
          .substring(passdir.length));
      }
    }

    socket.emit('recieveTree', verifiedPasswords);
  });
  return verifiedPasswords;
}

var getFileString = function(localPath) {
  return fs.readFileSync(localPath).toString();
}

var handler = function(req, res) {
  res.writeHead(200);
  res.sendFile(htmlPageSent);
};

app.use('/', express.static(__dirname));
app.get('/', handler);

var exec = function(command, hide, callback) {
  if (!hide) {
    console.log('Command executed: ' + command);
  }
  child_process.exec(command, function(err, res, stderr) {
    callback(res, stderr);
  });
}

var execSync = function(command, hide) {
  if (!hide) {
    console.log('Command executed: ' + command);
  }
  var res = child_process.execSync(command).toString();
  return res;
}

var server;

if (passphrase == '') {
  https.createServer({
  key: privKey,
  cert: cert
  }, app);
} else {
  https.createServer({
  key: privKey,
    passphrase: keyPassphrase,
  cert: cert
  }, app);
}
var io = socketIO.listen(server, {
  log: true
});
io.sockets.on('connection', function(socket) {
  socket.on('verify', function(input) {
    // Prevent code injection.
    if (usercheck.test(input.name)) {
      verify(input.name, input.pass, socket);
      console.log('User '+name+' (' + address.address + ':' + address.port + ') logged in.');
    } else {
      socket.emit('updateOut', 'Invalid username.');
    }
  });
});
server.listen(port);
