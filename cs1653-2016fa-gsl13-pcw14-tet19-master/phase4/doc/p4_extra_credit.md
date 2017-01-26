#Extra Credit - Phase 4
* For this phase, we added an integrity check to all files.
  * Since we assume that a File Server is malicious and may try to leak a file, we also assumed that a File Server may maliciously modify a file.
  * For this we used HMACing.
    * Thus, in addition to a symmetric key for file encryption, we also needed another symmetric key for the HMAC.
    * Every file was stored with a version number AND an HMAC.
    * Upon downloading a file, a use will HMAC the encrypted file contents to make sure that it matches the HMAC at the beginning of the file.
      * if the comparison between the computed hash and the hash in the file fails, then the file has been tampered with and our Client deletes the file and fails the download.

      
