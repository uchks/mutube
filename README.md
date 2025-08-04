<img src="https://unethicalcdn.com/private/mutube.png" height="150" alt="MuTube logo" align="left"/><br>
<p align="left">
  <strong>μTube (MuTube)</strong><br>
  Enhancing YouTube on Apple TV devices with<br>
<a href="https://github.com/reisxd/TizenTubeCobalt">TizenTube Cobalt's</a> userscript.<br>
</p>
</br>

### Features
- Removes Ads: No more interruptions from advertisements
- [SponsorBlock](https://sponsor.ajay.app/) Support: Automatically skip sponsored segments in videos.
- [DeArrow](https://dearrow.ajay.app/) Support: Remove clickbait and misleading video titles.
- Video Speed Control: Adjust playback speed.

## Build
1. Install [insert_dylib](https://github.com/Tyilo/insert_dylib).

    ```bash
    git clone https://github.com/Tyilo/insert_dylib
    cd insert_dylib
    xcodebuild
    cp build/Release/insert_dylib /usr/local/bin/insert_dylib
    ```

2. Run `make`. Make sure `Makefile` points to the correct IPA file.
   Different versions of YouTube will require different addresses to instrument.
   Both the Makefile and the `main.js` file need to be updated accordingly.

> [!NOTE]
> μTube (MuTube) has been tested using Frida 16.6.6 and YouTube 4.50.03 on an Apple TV 4K (3rd Generation). 

## Usage
Delete the original YouTube application from your Apple TV. <br>
Sideload the generated `mutube.ipa` onto your Apple TV using a tool like [Sideloadly](https://sideloadly.io/). <br>
Once installed, open the YouTube app and you should see a popup on the top right corner indicating that
TizenTube has loaded successfully.

> [!IMPORTANT] 
> HDR is not supported quite yet. See [Issue #2](https://github.com/Exaphis/mutube/issues/2) for more information.
