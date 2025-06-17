# μTube

MuTube enhances YouTube on Apple TV with [TizenTube Cobalt](https://github.com/reisxd/TizenTubeCobalt)'s userscript,
which removes ads and adds support for features like SponsorBlock.

## Setup

MuTube has been tested using Frida 16.7.19 and YouTube 4.50.03 on an Apple TV 4K.

1. Install [insert_dylib](https://github.com/Tyilo/insert_dylib).

    ```bash
    git clone https://github.com/Tyilo/insert_dylib
    cd insert_dylib
    xcodebuild
    cp build/Release/insert_dylib /usr/local/bin/insert_dylib
    ```

2. Download and extract the `gum-graft` binary from the [Frida releases page](https://github.com/frida/frida/releases) and place it in the `bin` directory.

    ```console
    $ wget https://github.com/frida/frida/releases/download/16.7.19/gum-graft-16.7.19-macos-arm64.xz -O bin/
    ...
    ‘bin/gum-graft-16.7.19-macos-arm64.xz’ saved
    $ xz -d bin/gum-graft-16.7.19-macos-arm64.xz
    $ chmod +x bin/gum-graft-16.7.19-macos-arm64
    ```

3. Run `make`. Make sure `Makefile` points to the correct IPA and the correct `gum-graft` binary.
   Different versions of YouTube will require different addresses to instrument.