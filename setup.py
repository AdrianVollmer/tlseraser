import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="tlseraser",
    version="0.0.2",
    author="Adrian Vollmer",
    author_email="adrian.vollmer@arcor.de",
    description="Eavesdrop on TLS connections with libpcap",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AdrianVollmer/tlseraser",
    packages=setuptools.find_packages(),
    scripts=[
        'bin/clone-cert.sh',
        'examples/flipper.py',
    ],
    package_data={
        'tlseraser': ['*.pem'],
    },
    install_requires=['netns'],
    entry_points={
        'console_scripts': [
            'tlseraser = tlseraser.__main__:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
)
