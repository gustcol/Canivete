# apt Cheatsheet

> Sanity is a spectrum.

## Import GPG Key
If you've ever run into the issue (and on Linux you will) of `The following signatures couldn't be verified because the public key is not available: NO_PUBKEY ED444FF07D8D0BF6`, here's how you can fix it:
```sh
apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys 7D8D0BF6
```
