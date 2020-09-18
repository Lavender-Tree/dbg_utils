from setuptools import setup, find_packages
from setuptools.command.install import install
import os
import shutil


class IDPSSInstall(install):
    """Post-installation for installation mode."""
    def run(self):
        # install idpss
        idpss_path = '/usr/bin/idpss'
        shutil.copy('dbg_utils/idp_server.py', idpss_path)
        os.system('chmod +x ' + idpss_path)
        
        # install idpss systemd service
        shutil.copy('idpss/systemd/idpss.service', '/etc/systemd/system/')
        
        install.run(self)


setup(
    name = "dbg_utils",
    keywords = ["pip", "pwn", "dbg"],
    description = "dbg utils for gdb",
    long_description_content_type='text/markdown',
    license = "MIT Licence",

    setup_requires=['setuptools_scm'],
    use_scm_version=True,

    author = "agfn",
    author_email = "lavender.tree9988@gmail.com",
    url='https://github.com/agfn/dbg_utils',

    packages = find_packages(),
    include_package_data = True,
    platforms = "any",
    install_requires = [],
    
    cmdclass={
        'install': IDPSSInstall,
    },
)