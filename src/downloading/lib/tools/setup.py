import os
from setuptools import setup, find_packages
from glob import glob


def find_files(glob_filter):
    files = []
    for filename in glob(glob_filter, recursive=True):
        if os.path.isfile(filename):
            files.append(filename)
    return files


setup(
    name='matool',
    description='matool',
    version='0.1.0',
    packages=['matool'],
    url='',
    license='MIT',
    author='Christoph Schwarzenberg',
    author_email='c.schwarzenberg@tum.de',
    install_requires=[
    ],
    data_files=[
    ],
    include_package_data=True,
)
