### galvanize ###

galvanize is a rust utility that will encrypt and decrypt data. The key is
derived from a password using PBKDF2 (using SHA-256, 1000 iterations, and no
salt because I'm lazy (this may change in the future)) and the data is
encrypted using AES-256 GCM. The cryptography implementation is from the [ring
crate](https://briansmith.org/rustdoc/ring/).

Combined with the following autocommand group (put it in .vimrc), it enables
editing encrypted data straight from vim:

    augroup galvanize
      autocmd BufReadPre,FileReadPre *.glv set viminfo=
      autocmd BufReadPre,FileReadPre *.glv set noswapfile noundofile nobackup
      autocmd BufReadPre,FileReadPre *.glv let $password = inputsecret("Password: ")
      autocmd BufReadPre,FileReadPre *.glv let passwordset = 1
      autocmd BufReadPre,FileReadPre *.glv set bin
      autocmd BufReadPre,FileReadPre *.glv set noshelltemp
      autocmd BufReadPost,FileReadPost *.glv silent! '[,']!galvanize -d -p $password
      autocmd BufReadPost,FileReadPost *.glv if v:shell_error | throw "Error reading file - bad password?" | endif
      autocmd BufReadPost,FileReadPost *.glv set nobin

      autocmd BufWritePre,FileWritePre *.glv if exists("passwordset") | let $outpassword = $password | endif
      autocmd BufWritePre,FileWritePre *.glv if !exists("passwordset") | let $outpassword = inputsecret("Password: ") | endif
      autocmd BufWritePre,FileWritePre *.glv if !exists("passwordset") | let $outpassword2 = inputsecret("Confirm password: ") | endif
      autocmd BufWritePre,FileWritePre *.glv if !exists("passwordset") && $outpassword != $outpassword2 | throw "Passwords don't match - aborting write" | endif
      autocmd BufWritePre,FileWritePre *.glv set bin
      autocmd BufWritePre,FileWritePre *.glv set noshelltemp
      autocmd BufWritePre,FileWritePre *.glv silent! '[,']!galvanize -e -p $outpassword
      autocmd BufWritePost,FileWritePost *.glv set nobin
      autocmd BufWritePost,FileWritePost *.glv u
    augroup END

This is almost certainly not foolproof. I imagine the protection offered will
only defeat an unmotivated attacker.
