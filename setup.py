from setuptools import setup, find_packages

setup(
    name="obfutil",
    version="3.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "obfutil=obfutil.ui.cli.main:main",
        ],
    },
    install_requires=[
        "cryptography>=3.4",
        "astor>=0.8",
    ],
    python_requires=">=3.7",
)