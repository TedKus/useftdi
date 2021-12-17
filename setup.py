from setuptools import setup, find_packages


setup(name='useftdi',
      version='0.7.17',
      description="""
                  A library of software drivers to interface with various
                  I2C IC's utilizing FTDI I2C dongles.
                  Requires Python 3.6.xx or later.
                  """,
      url=r'https://github.com/TedKus/useftdi',
      author='Ted Kus, Anna Giasson',
      author_email=' ', license='None',
      packages=find_packages(), zip_safe=False,
      classifiers=[
                   'Development Status :: 3 - Alpha',
                   'Environment :: Console',
                   'Intended Audience :: Developers',
                   'Programming Language :: Python'
                   ],
      install_requires=[
                        'pyftdi',
                        ],
      )
