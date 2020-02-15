from setuptools import setup, find_packages

setup(
    name='pycap',
    version='0.1',
    packages=find_packages(exclude=('tests', 'tests.*', 'examples', 'examples.*', 'docs')),
    auther='Yeefea',
    auther_email='yifei.shen@yahoo.com',
    keywords='network, analyzer, sniffer',
    description='A network analyzer implemented in pure Python',
    url='https://github.com/Blueswing/pycap',
    python_requires='>=3.6',
    zip_safe=False
)
