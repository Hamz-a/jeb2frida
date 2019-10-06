# jeb2frida

Generate Frida hooks automatically using JEB. This is done using a naïve signature based algorithm:
1. Search for a unique magic string such as [**"Certificate pinning failure!"**][okhttpmagicstr] in OkHttp's case;
2. Get the class where the string resides and extract the class path;
3. Loop through each method of the above class, and check if the parameters matches our signature;
4. Optionally check the return value.

For more information, see: [Automated Frida hook generation with JEB][blogpost]


## Usage
1. Put the *GenerateFridaHooks.py* script in the JEB scripts folder.
2. Edit the script accordingly
3. Run it from JEB GUI or use the following command:

```bash
./jeb_macos.sh -c --srv2 --script=GenerateFridaHooks.py -- "/path/to/apk/file.apk"
```

## Sample output

```bash
➜  jeb-pro ./jeb_macos.sh -c --srv2 --script=GenerateFridaHooks.py -- "/path/to/apk/file.apk"
<JEB startup header omitted>

🔥 JEB scripting
{JebFridaHookArtifact > JebFridaHookArtifact}: 4956 resource files were adjusted
Attempting to merge the multiple DEX files into a single DEX file...
<JEB processing omitted>
{JebFridaHookArtifact > JebFridaHookArtifact}: DEX merger was successful and produced a virtual DEX unit

🔥 Fresh Frida Hooks
----------------------------------------------------------------------------------------------------
'use strict';
    // Usage: frida -U -f com.example.app -l generated_hook.js --no-pause
    Java.perform(function() {

        var okhttp3_CertificatePinner0 = Java.use('<omitted>');
        var findMatchingPins0 = okhttp3_CertificatePinner0.a.overload('java.lang.String');
        findMatchingPins0.implementation = function(hostname) {
            console.log('[+] okhttp3.CertificatePinner.findMatchingPins(' + hostname + ') # <omitted>()');
            return findMatchingPins0.call(this, ''); // replace hostname with empty string
        };

        var okhttp3_CertificatePinner1 = Java.use('com.squareup.okhttp.CertificatePinner');
        var findMatchingPins1 = okhttp3_CertificatePinner1.findMatchingPins.overload('java.lang.String');
        findMatchingPins1.implementation = function(hostname) {
            console.log('[+] okhttp3.CertificatePinner.findMatchingPins(' + hostname + ') # com.squareup.okhttp.CertificatePinner.findMatchingPins()');
            return findMatchingPins1.call(this, ''); // replace hostname with empty string
        };

    });

----------------------------------------------------------------------------------------------------
Done.
```



[okhttpmagicstr]: https://github.com/square/okhttp/blob/ba2c676aaf2b825528955f61dd43004a5bd9ca98/okhttp/src/main/java/okhttp3/CertificatePinner.kt#L175
[blogpost]: https://bhamza.me/2019/10/06/Automated-Frida-hook-generation-with-JEB.html
