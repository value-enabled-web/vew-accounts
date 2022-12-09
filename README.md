# ⚡️ vew-accounts

Super simple account system and gateway to LNBits intended to be used by [`vew-reader`](https://github.com/seetee-io/vew-reader) to make LN payments.

## How to Run

1. `cp .env.example .env`
1. Create a wallet on [legend.lnbits.com](https://legend.lnbits.com/), enable the _User Manager_ extension, and add its credentials to `.env`. See `.env.example` for which credentials to add.
1. `npm install`
1. `npm start`; or `npm run dev` for hot reloading

## Note

This is just a quick prototype implementation.
It is most certainly buggy and not secure.
Do not use it in a production setting.
