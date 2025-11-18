# as4pgc
Hide files inside audio files.

Use "Audio Steganography for Pretty Good Concealment" to compress, encrypt, and hide small files of any type inside compressed audio files (e.g. MP3, FLAC, OGG) or inside uncompressed .WAV files.

## Installation
```sh
  pip install as4pgc
  
  # install dependencies:
  pip install -r requirements.txt
  
  # in linux:
  sudo apt install ffmpeg
  sudo apt install sox libsox-fmt-mp3
  sudo apt install libsox-fmt-opus
```
For Windows you can download ffmpeg from here:
https://www.ffmpeg.org/

## How to use it?
Hide a file of any type inside an .mp3 file:
```sh
  as4pgc -w secret.zip carrier.mp3
```
Use option -p to activate plots and track signal processing steps.

Use option -v to output details.
```sh
  as4pgc -p -v -w secret.zip carrier.mp3
```

Then recover the hidden file:
```sh
  as4pgc -r stego.mp3
```

Use the option -h for more information:

```sh
  as4pgc -h
```

Configuration settings can be adapted in config.ini.
For detailed documentation check the Article in Code Project. The link is provided further below.

## PyPi Project

https://pypi.org/project/as4pgc/

## Article in Code Project

https://www.codeproject.com/Articles/5313626/Audio-Steganography-for-Pretty-Good-Concealing-AS4

## Article in GitHub

https://github.com/ClarkFieseln/AS4PGC

## License

(c) 2026 Clark Fieseln

This repository is licensed under the MIT license. See LICENSE for details.
