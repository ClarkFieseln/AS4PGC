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

# install dependencies:
-----------------------

sudo apt update

sudo apt upgrade

# in linux:
sudo apt install sox libsox-fmt-mp3
sudo apt install libsox-fmt-opus
sudo apt install ffmpeg
sudo apt-get install -y python3-dev libasound2-dev

python3 -m pip install --upgrade pip

pip install --upgrade pip setuptools

pip install --use-pep517 simpleaudio

pip install wheel

pip install XXXXXXXXXXXXXXXX

pip install XXXXXXXXXXXXXXXX


######################
for test in test.pypi:
######################

# inside the folder with the setup.py file type:

python3 -m pip install -e . --config-settings editable_mode=compat

python3 -m build

twine check dist/*

cd as4pgc

# test if the local installation works:

as4pgc -V

-----------------------------------------------------------------------------

pip install -I --user idna

# inside the folder with the setup.py file type:

python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

      user: __token__
      pwd: (paste token here)

# now copy the text at the beginning of the page, see e.g.:
   https://test.pypi.org/project/as4pgc/1.1.7/

# the text may be something like this:
# pip install -i https://test.pypi.org/simple/ as4pgc==1.1.7
# you may first want to create a virtual environment:
   virtualenv venv_test
   cd venv_test
   source bin/activate
   (or source local/bin/activate ?)

# repeat steps described in section "before you start"

# after that type:
   pip install -i https://test.pypi.org/simple/ as4pgc==1.1.7
   (you may need to repeat if the first try fails!)

# now the command as4pgc is available for use, check installation path with:
   pip show as4pgc
# change to that 'Location', e.g.:
   cd /home/<user>/.pyenv/versions/3.10.14/lib/python3.10/site-packages/as4pgc
   as4pgc -V
   pip list | grep as4pgc

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



