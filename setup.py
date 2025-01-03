from setuptools import setup, find_packages

setup(
    name="m_map",
    version="1.6.0",
    packages=find_packages(),
    install_requires=[
        'colorama',
        'pyfiglet',
        'python-nmap',
        'requests'
    ],
    python_requires='>=3.6',
) 