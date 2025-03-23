from setuptools import setup, find_packages

setup(
    name='sql-scanner-injection',
    version='0.1.0',
    author='PhanTheToan',
    author_email='phantoan3009@gmail.com',
    description='A project for scanning SQL injection vulnerabilities',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/PhanTheToan/sql-scanner-injection',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=open('requirements.txt').read().splitlines(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)