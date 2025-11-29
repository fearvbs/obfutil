from setuptools import setup, find_packages

setup(
    name="obfutil",
    version="3.2",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.4",
        "astor>=0.8"
    ],
    entry_points={
        'console_scripts': [
            'obfutil=obfutil.ui.cli.main:main',
        ],
    },
    python_requires=">=3.9",
)


