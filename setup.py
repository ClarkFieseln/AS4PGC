import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

__version__ = "1.0.3"

# This call to setup() does all the work
setup(
    name="as4pgc",
    version=__version__,
    description = "Audio Steganography for Pretty Good Concealing - hide message file in audio file",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/ClarkFieseln/as4pgc",
    author="Clark Fieseln",
    author_email="",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Topic :: Security",
    ],
    packages=["as4pgc"],
    include_package_data=True,
    install_requires=['SoundFile','matplotlib','dataclasses','cryptography','numpy','scipy','bitarray','tinytag','simpleaudio'],
    dependency_links=['https://www.ffmpeg.org/'],
    keywords=['steganography','stego','mp3','audio','hide','cryptography','encryption','compression','security','cybersecurity'],
    entry_points={
        "console_scripts": [
            "as4pgc=as4pgc.AS4PGC:main",
        ]
    },
)


