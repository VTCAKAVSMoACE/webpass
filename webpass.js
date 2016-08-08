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
  keyPassphrase = 'pass',
  htmlPageSent = '/index.html',
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
    address = address.substring(address.lastIndexOf(':') + 1);

    console.log('User ' + name + ' (' + address + ') attempted to unlock their key.');

    /**
     *
     * Define the GPG private key for the user.
     *
     */
    
    var gpgPrivKey = openpgp.key.readArmored(execSync(
      'gpg --armor --export-secret-key "' + name + '"'), false).keys[0];

    // Verify that key exists.
    if (gpgPrivKey == undefined) {
      console.log('No GPG key found for user ' + name + ' (' + address + ').');
      socket.emit('updateOut', 'Invalid login.');
      return;
    }

    // Verify that the given passphrase unlocks the user's private key.
    if (!gpgPrivKey.decrypt(pass)) {
      socket.emit('updateOut', 'Invalid login.');
      console.log('User ' + name + ' (' + address + ') failed to provide a valid passphrase.');
      return;
    }

    socket.emit('updateOut', 'Validated.');

    // Define all verified passwords and also send the tree to the user.
    var verifiedPasswords = sendTree(name, socket);

    // Define future listeners, but don't give them values yet.
    var getPass,
      makePass,
      makeFold;

    /**
     *
     * getPass listener.
     *
     * Function objectives:
     *   - Retrieve a password for the user.
     *     - Password will be verified (if their key cannot decrypt the message, it will not be sent).
     *     - Password will be sanitized (prevent code injection).
     *
     */
    
    getPass = function(passname) {

      console.log('User ' + name + ' (' + address + ') queried for password ' + passname);

      /**
       *
       * Check against bad names - code injection and arbitrary write prevention.
       *
       */
      
      if (!filecheck.test(passname) || passname.indexOf('..') != -1) {
        socket.emit('updateOut', 'Bad character in query.');
        return;
      }

      /**
       *
       * Remove the listener for retrieving the password.
       *
       * Doing this prevents a user from quickly retrieving many passwords. If the
       *    user were able to do that, they may be able to prevent other users from
       *    viewing passwords or, in extreme cases, crashing the node session or 
       *    even the server.
       *
       */
      
      socket.removeAllListeners('retrievePass');


      /**
       *
       * All passwords reqs are sent to the server with the form './<passname>'.
       *    This cleans up the password, then adds the password store directory
       *    to the front of it as an absolute path to the password. This removes
       *    the chance for arbitrary writes.
       *
       */
      
      passname = passdir + passname.substring(2);

      /**
       *
       * Start the decryption process.
       *
       */
      
      try {
        
        /**
         *
         * Armor the .gpg file, overriding it if it already exists.
         *
         */
        
        exec('gpg --enarmor --yes ' + passname, false, function(e, so, se) {
          
          // If we get a subprocess execution error, throw it.
          if (e) throw e;
          
          /**
           *
           * Setup the options for decryption.
           *
           * Due to a bug in openpgp.js (which still hasn't been fixed), 
           *    we must replace "ARMORED FILE" with "MESSAGE" in both the
           *    header and footer of the armored .gpg password file.
           *
           */
          
          var options = {
            // Grab the message through FS and parse it. Its name is <pass>.asc.
            message: openpgp.message.readArmored(getFileString(
              passname + '.asc').split('ARMORED FILE').join(
              'MESSAGE')),
            
            // Since gpgPrivKey is now unlocked, we can use it as we wish.
            privateKey: gpgPrivKey
          };
          
          console.log('Options built and validated for user ' + name +
            ' (' + address + ').');

          
          
          openpgp.decrypt(options).then(function(plaintext) {
            
            console.log('Decryption succeeded for user ' + name +
              ' (' + address + ').');
            
            // Send the user the password.
            socket.emit('updateOut', 'Password ' + passname.split(
                '/').pop() +
              ' unlocked: ' + plaintext.data);
            
            console.log('Sent password '+ passname + ' for user ' + name + ' (' + address + ').');
            
            // Re-enable the listener so that the user can get another.
            socket.on('retrievePass', getPass);
          });
        });
      } catch (exc) {
        
        socket.emit('updateOut', 'Invalid target.');
        
        console.log('User ' + name + ' (' + address + ') failed to provide a valid target.');
        
        // Double-check to prevent excessive listeners.
        socket.removeAllListeners('retrievePass');
        socket.on('retrievePass', getPass);
        
        return;
      }
    }

    // Enable the getPass listener.
    socket.on('retrievePass', getPass);

    /**
     *
     * makePass listener.
     *
     * Function objectives:
     *   - Allow the user to write new passwords or overwrite old ones.
     *     - If the user is not permitted to overwrite (not a recipient
     *         as defined by the message header), do not permit an
     *         overwrite.
     *
     */
    
    makePass = function(passdetails) {

      // Disable this listener, just in case.
      socket.removeAllListeners('makePass');

      // Grab the specifications for this new password.
      var passpath = passdetails.newpassname,
        password = passdetails.newpassword,
        recipients = passdetails.recipients;

      // Prevent code injection and superdirectory access.
      if (!filecheck.test(passpath) || passpath.indexOf('..') != -1) {
        socket.emit('updateOut', 'Bad password path.');
        socket.on('makePass', makePass);
        return;
      }

      /**
       *
       * Check if the password already exists. If it does, only continue
       *    if the user is actually verified to overwrite them (as defined
       *    by the password tree we used earlier).
       *
       */
      
      try {
        
        // Throws an error if the file does not exist.
        fs.accessSync(passdir + passpath, fs.F_OK);
        
        // If the user can't overwrite this password...
        if (verifiedPasswords.indexOf(passpath.substring(2)) == -1) {
          
          console.log('User ' + name + ' (' + address + ') attempted to overwrite password ' +
            passpath + '.');
          
          socket.emit('updateOut', 'Cannot overwrite key (auth).');
          
          // Re-enable the listener - it's possible that this was in error.
          socket.on('makePass', makePass);
          
          return;
          
        }
      } catch (exc) {}

      /**
       *
       * Prevent code injection. Since this uses ' to prevent any $ access,
       *    replace all ' with '"'"'.
       *
       */
      
      password = password.split("'").join("\'\"\'\"\'");

      // Initialize the recipients string so we can concatenate to it.
      recipstr = "";

      for (ind = 0; ind < recipients.length; ind++) {
        
        console.log('User ' + name + ' attempted to add recipient ' +
          recipients[ind] + ' to password ' + passpath + '.');
        
        // If one of the recipients fails the regex, cancel the write.
        if (!usercheck.test(recipients[ind])) {
          
          socket.emit('updateOut', 'Invalid username: ' + recipients[ind]);
          
          // Re-enable the listener.
          socket.on('makePass', makePass);
          
          return;
          
        } else 
          // Check each of the recipients if they have keys as well.
          if (execSync('gpg --armor --export-secret-key "' +
            recipients[ind] + '"').valueOf() == '') {
            
            socket.emit('updateOut', 'Recipient ' + recipients[ind] +
            ' does not exist.');
            
            // Re-enable the listener.
            socket.on('makePass', makePass);
            
            return;
            
        }
        
        // Add the recipient to the exported key.
        recipstr += ' -r ' + recipients[ind];
        
      }

      // Catch any errors and generically report it to user.
      try {
        
        /**
         *
         * Use gpg to encrypt the file. The steps go as such:
         *    1) Pipe the password into gpg.
         *    2) Add the recipients (+ recipstr +)
         *    3) Trust all the keys (--always-trust)
         *    4) Allow overwrite (--yes, --batch)
         *    5) Output at specified location (-o)
         *
         */
        
        exec("echo '" + password + "' | gpg -e" + recipstr +
          " --always-trust --yes --batch -o " + passdir + passpath, true,
          function(e, stdout, stderr) {
            
            // If there's no stderr, we're all good, don't throw errors.
            if (stderr == undefined) {
              return;
            }
          
            // If there's a subprocess execution error, throw it.
            if (err) {
              throw err;
            }
          
            // If the encryption failed for whatever reason...
            if (stderr.indexOf('encryption failed') != -1) {
              
              // Check for a missing pubkey.
              if (stderr.indexOf('public key not found') != -1) {
                
                var lines = stderr.split('\n');
                
                // Inform user of the first missing key.
                for (ind = 0; ind < lines.length; ind++) {
                  
                  // If found on this line...
                  if (lines[ind].indexOf('public key not found') != -1) {
                    
                    // Record the failed user.
                    var failedUser = lines[ind].substring(5);
                    failedUser = failedUser.substring(0, failedUser.indexOf(
                      ':'));
                    
                    socket.emit('updateOut', 'No key for user: ' +
                      failedUser);
                    
                    // Re-enable the listener.
                    socket.on('makePass', makePass);
                    
                    return;
                    
                  }
                }
              }
              
              // If there's another error, go into generic error.
              throw new Error();
              
            }
          
          });
        
      } catch (exc) {
        
        console.log('User '+name+' (' + address + ') threw an unknown encryption error.')
        
        socket.emit('updateOut', 'Encryption error.');
        
        // Re-enable the listener.
        socket.on('makePass', makePass);
        return;
      }

      socket.emit('updateOut', 'Password ' + passpath.split('/').pop() +
        ' saved.');
      socket.emit('editSuccess', null);
      
      // Update the local git.
      var gitupdate = execSync("cd " + passdir +
        "; git add -A; git commit -m 'User " + name +
        " updated password " + passpath + ".'", false).toString();
      
      console.log('git updated: ' + gitupdate);
      
      // Re-enable the listener.
      socket.on('makePass', makePass);
    }

    // Enable the listener.
    socket.on('makePass', makePass);

    /**
     *
     * makeFold listener.
     *
     * Function objectives:
     *   - Allow the user to make subdirectories.
     *
     */
    
    makeFold = function(foldname) {

      // Stop the listener for now.
      socket.removeAllListeners('makeFold');

      // Check against code injection and superdirectory access.
      if (!foldcheck.test(foldname) || foldname.indexOf('..') != -1) {
        socket.emit('updateOut', 'Bad folder name.');
        socket.on('makeFold', makeFold);
        return;
      }

      // Catch any errors and report it generically to the user.
      try {
        
        // Make a directory with no prompt for existing directories (-p).
        exec("mkdir -p " + passdir + foldname, false, function(err, stdout,
          stderr) {
          
          // If there's no stderr, continue.
          if (stderr == undefined) {
            return;
          }
          
          // Throw a generic error.
          throw new Error();
        });
      } catch (exc) {
        
        socket.emit('updateOut', 'Folder creation error.');
        
        // Re-enable the listener.
        socket.on('makeFold', makeFold);
        
        return;
        
      }
      
      console.log('User ' + name + ' (' + address + ') made directory ' + foldname);
      
      socket.emit('updateOut', 'Subdirectory ' + foldname +
        ' made successfully.');
      socket.emit('editSuccess', null);
      
      // Re-enable the listener.
      socket.on('makeFold', makeFold);

    }

    // Enable the listener.
    socket.on('makeFold', makeFold);

  } catch (exc) {
    
    console.log('User ' + name + ' (' + address + ') caused an unhandled error.');
    
    console.log('Stack trace:');
    console.log(exc.stack);
    
    socket.emit('updateOut', 'Unknown error.');
    
  }
  
}

/**
 *
 * sendTree helper function.
 *
 * Function objectives:
 *   - Build and send a list of verified passwords.
 *
 * Returns:
 *   - The array of verified passwords. 
 *     - Used to check for password editing permission.
 *
 */

var sendTree = function(name, socket) {
  
  // Store the verified password array.
  var verifiedPasswords = [], address = socket.handshake.address;
  address = address.substring(address.lastIndexOf(':') + 1);

  
  // Run the gpgfind helper script with the target password store.
  exec('bash gpgfind "' + passdir + '"', false, function(stdout, stderr) {
    
    // Make variables for the password list and the key owner lists.
    var passwords = stdout.split('\n'),
      ownersToCheck = stderr.split('\n');

    // Remove the final password, which is empty.
    passwords.pop();

    for (ind = 0, passind = 0; ind < ownersToCheck.length; ind += 1) {
      
      // Whenever this line is encountered, move to the next password
      // in the password list. This is a tricky way of finding passwords
      // for when there are more than one recipients.
      if (ownersToCheck[ind].indexOf(
          'gpg: decryption failed: secret key not available') != -1) {
        passind += 1;
      } else 
        
        // If that line isn't found, check for the target key name.
        if (ownersToCheck[ind].indexOf(name) != -1) {
          
          // Pass this password to the verified password list.
          verifiedPasswords.push(passwords[passind].substring(passdir.length));
          
          console.log('User ' + name + ' (' + address + ') was marked as authorized for password ' + passwords[passind].substring(passdir.length));
      }
    }

    // Send the tree.
    socket.emit('recieveTree', verifiedPasswords);
    
  });
  
  // Inform verify function of the passwords that this user is verified for.
  return verifiedPasswords;
  
}

// Helper method for grabbing file contents.
var getFileString = function(localPath) {
  
  return fs.readFileSync(localPath).toString();
  
}

// Main page request handler for the HTTPS server instance.
var handler = function(req, res) {
  
  res.writeHead(200);
  res.sendFile(htmlPageSent);
  
};

// Establish the express instance.
app.use('/', express.static(__dirname));
app.get('/', handler);

// Helper method for executing subprocesses.
var exec = function(command, hide, callback) {
  
  if (!hide) {
    console.log('Command executed: ' + command);
  }
  
  child_process.exec(command, function(err, res, stderr) {
    callback(res, stderr);
  });
  
}

// Helper method for executing subprocesses when STDERR doesn't matter.
var execSync = function(command, hide) {
  
  if (!hide) {
    console.log('Command executed: ' + command);
  }
  
  return child_process.execSync(command).toString();
  
}

var server;

// Define the server instance.
// If no passphrase, don't use one.
if (keyPassphrase == '') {
  
  server = https.createServer({
    key: privKey,
    cert: cert
  }, app);
  
} else {
  
  server = https.createServer({
    key: privKey,
    passphrase: keyPassphrase,
    cert: cert
  }, app);
  
}

// Define the websocket handler.
var io = socketIO.listen(server, {
  log: true
});

// Start listening for websocket connections.
io.sockets.on('connection', function(socket) {
  
  // Listen for verify requests.
  socket.on('verify', function(input) {
    var address = socket.handshake.address;
    address = address.substring(address.lastIndexOf(':') + 1);
    // Prevent code injection.
    if (usercheck.test(input.name)) {
      
      verify(input.name, input.pass, socket);
      console.log('User ' + input.name + ' (' + address + ') logged in.');
      
    } else {
      socket.emit('updateOut', 'Invalid login.');
    }
    
  });
  
});

// Start listening for HTTPS connections.
server.listen(port);
