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
        'twisted[tls] >= 18.4.0',
        'attrs =< 19.1',
        'pyopenssl',
        'txsni',
        'txacme',
        'incremental',
    ],
    zip_safe=False,
    setup_requires=["incremental"],
    use_incremental=True,
)
