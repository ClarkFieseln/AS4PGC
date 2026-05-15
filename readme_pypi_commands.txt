###################################################################################################################
NOTE:
#####
This readme is only for "contributors" of the project.
You may use it as a guide in case you want to create variants of this tool on another PyPI or Test PyPI repository.
But then you need to change the name of your tool and create the corresponding project.
###################################################################################################################


#################
before you start:
#################
# (optional) if required first activate an evironment with the "same" python version
# cd at same level of project
python3 -m venv as4pgc_venv
source as4pgc_venv/bin/activate

# install dependencies:
-----------------------
sudo apt update
sudo apt upgrade
sudo apt install -y python3-dev
sudo apt install -y build-essential
sudo apt install -y libasound2-dev

# linux packages needed:
sudo apt install sox libsox-fmt-mp3
sudo apt install libsox-fmt-opus
(see e.g. https://ubuntu.pkgs.org/25.04/ubuntu-universe-arm64/libsox-fmt-opus_14.4.2+git20190427-5build1_arm64.deb.html)
sudo apt install ffmpeg
# pip packages needed
python3 -m pip install --upgrade pip
python3 -m pip install -U \
  twine \
  setuptools \
  wheel \
  build \
  packaging
python3 -m pip install -U \
  requests \
  requests-toolbelt \
  urllib3
python3 -m pip install matplotlib
python3 -m pip install soundfile
python3 -m pip install scipy
python3 -m pip install bitarray
python3 -m pip install pipreqs
python3 -m pip install tinytag
python3 -m pip install simpleaudio


######################
for test in test.pypi:
######################
# inside the folder with the setup.py file type:
python3 -m pip install -e . --config-settings editable_mode=compat
# rm -rf build dist *.egg-info
python3 -m build
twine check dist/*
cd as4pgc

# test if the local installation works:
as4pgc -V

-----------------------------------------------------------------------------

pip install -I idna  # installs into the currently active Python environment
(pip install -I --user idna   # installs into your user site-packages directory)

# *** back inside the folder with the setup.py file type ***:
python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
      user: __token__
      pwd: (paste token here)

# if you copy the text at the beginning of the page, see e.g.:
#   https://test.pypi.org/project/as4pgc/1.1.7/
# it will not find the packages
# so, instead do:
    pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple as4pgc==1.1.7

# the text may be something like this:
# pip install -i https://test.pypi.org/simple/ as4pgc==1.1.7
# you may first want to create a virtual environment:
    python3 -m venv as4pgc_venv
    source as4pgc_venv/bin/activate

# repeat steps described in section "before you start" to install APT dependencies

# after that type:
    pip install -i https://test.pypi.org/simple/ as4pgc==1.1.7
    (you may need to repeat if the first try fails!)

# now the command as4pgc is available for use, check installation path with:
    pip show as4pgc

# change to that 'Location', e.g.:
    cd /home/<user>/.pyenv/versions/3.10.14/lib/python3.10/site-packages/as4pgc
    as4pgc -V
    pip show as4pgc

# leave the virtual environment:
    deactivate

------------------------------------------------------------------------------

####################
for release in pypi:
####################

# TODO: setup.py install is deprecated -> adapt procedure as required.

# inside the folder with the setup.py file type:

python3 setup.py sdist bdist_wheel

twine check dist/*

twine upload dist/*

# enter user and password (or token), e.g.:

      user: __token__
      pwd: (paste token here)

# now the pypi project is available here:
   https://pypi.org/project/as4pgc

# install on the machine you want to use the tool with:
   pip install as4pgc

# now the command as4pgc is available for use

