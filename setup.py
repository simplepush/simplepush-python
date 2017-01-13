from distutils.core import setup
setup(
  name = 'simplepush',
  packages = ['simplepush'],
  version = '1.0.3',
  description = 'Simplepush python library',
  author = 'Timm Schaeuble',
  author_email = 'contact@simplepush.io',
  url = 'https://simplepush.io',
  keywords = ['push', 'notification', 'android', 'logging', 'app', 'simple', 'encrypted'],
  license = 'MIT',
  install_requires=[
        'requests',
        'pycrypto'
      ],
  classifiers = [],
)
