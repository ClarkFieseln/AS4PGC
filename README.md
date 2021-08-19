# as4pgc
Use "Audio Steganography for Pretty Good Concealing" to hide small files inside compressed audio files (e.g. mp3, flac, ogg) or uncompressed .wav files.

## Installation
```sh
  pip install as4pgc
```
You also need to install ffmpeg. Download it from here:
https://www.ffmpeg.org/

## How to use it?
Hide a file of any type inside an .mp3 file:
```sh
  as4pgc -w secret.zip carrier.mp3
```
Use option -p to activate plots and track signal processing steps.

Use option -v to output details.

Then recover the hidden file:
```sh
  as4pgc -r stego.mp3
```

Use the option -h for more information:

```sh
  as4pgc -h
```

Configuration settings can be adapted in config.ini (detailed documentation to be provided soon).
## GitHub Project

https://github.com/ClarkFieseln/as4pgc

## License

(c) 2021 Clark Fieseln

This repository is licensed under the MIT license. See LICENSE for details.
