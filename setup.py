"""Simplepush setup script."""
from distutils.core import setup

setup(
    name='simplepush',
    packages=['simplepush'],
    version='2.0.0',
    description='Simplepush Python Library',
    author='Timm Schaeuble',
    author_email='contact@simplepush.io',
    url='https://simplepush.io',
    keywords=[
        'actionable notifications', 'push', 'notification', 'android', 'ios', 'encryption'
    ],
    license='MIT',
    install_requires=[
        'requests',
        'cryptography',
        'aiohttp'
      ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
    ],
)
