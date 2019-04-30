import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="tlseraser-avollmer",
    version="0.1",
    author="Adrian Vollmer",
    author_email="adrian.vollmer@arcor.de",
    description="Helps you to eavesdrop on TLS connections with libpcap",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AdrianVollmer/tlseraser",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Linux",
    ],
)
