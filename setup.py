from setuptools import setup

setup(
    name='accountCompromiseDetector',
    version='1.0',
    packages=['accountCompromiseDetector'],
    url='',
    license='',
    author='Justin Beyer',
    author_email='jusbeyer@gmail.com',
    description='Tests Accounts for compromise',
    install_requires=['python-ldap', 'keyring']
)
