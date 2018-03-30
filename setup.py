import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='mp-accounts',
    version='0.0.1',
    packages=['accounts'],
    install_requires=['python-social-auth'],
    include_package_data=True,
    license='TBD',
    description='Account Management',
    long_description=README,
    url='https://github.com/Ecotrust/mp-accounts',
    author='Ecotrust',
    author_email='ksdev@ecotrust.org',
    classifiers=[
        'Environment :: Web Development',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: TBD',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
