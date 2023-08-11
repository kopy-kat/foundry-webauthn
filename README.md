# foundry-webauthn

This repo hooks up the FCL's webauthn lib to foundry testing. The repo is meant as a quick demonstration for how to create keys and sign messages in the right format to be verified by the FCL Webauthn library.

To use this repo:

1. Clone the repo
2. Run `yarn` to install dependencies
3. Run `forge install` to install foundry dependencies
4. Run `forge test --ffi` (you need to pass `--ffi` in order to run the TS script that generates the passkeys and webauthn signature)
