from setuptools import setup

setup(
    name='rproxy',
    description='A super simple reverse proxy.',
    long_description=open("README.rst").read(),
    author='Amber Brown',
    author_email='hawkowl@atleastfornow.net',
    packages=['rproxy', 'twisted.plugins'],
    package_dir={"": "src"},
    install_requires=[
        'twisted >= 17.1.0',
        'pyopenssl',
        'txsni',
        'incremental',
    ],
    zip_safe=False,
    setup_requires=["incremental"],
    use_incremental=True,
)
