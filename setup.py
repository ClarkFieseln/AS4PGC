import pathlib
from setuptools import setup
import sys

if sys.version_info < (3,6):
    print("as4pgc requires Python 3.6 or higher, please upgrade")
    sys.exit(1)

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

__version__ = "1.1.7"

# This call to setup() does all the work
setup(
    name="as4pgc",
    version=__version__,
    description = "Audio Steganography: compress, encrypt and hide a secret file inside an audio file (MP3, WAV, OGG, FLAC, OPUS, ..)",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/ClarkFieseln/AS4PGC",
    author="Clark Fieseln",
    author_email="",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Developers",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
    packages=["as4pgc"],
    include_package_data=True,
    install_requires=['SoundFile','matplotlib','dataclasses','cryptography>=46.0.3','numpy','scipy','bitarray','tinytag','simpleaudio'],
    dependency_links=['https://www.ffmpeg.org/'],
    keywords=['steganography','stego','audio','hide','cryptography','encryption','compression','security','cybersecurity','mp3','flac','ogg','opus','wav','linux'],
    entry_points={
        "console_scripts": [
            "as4pgc=as4pgc.AS4PGC:main",
        ]
    },
    project_urls={  # Optional
    'Source': 'https://github.com/ClarkFieseln/as4pgc',
    },
)
