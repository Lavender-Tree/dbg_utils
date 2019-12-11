from setuptools import setup, find_packages
from setuptools.command.install import install
import os

class IDPSSInstall(install):
    """Post-installation for installation mode."""
    def run(self):
        # PUT YOUR POST-INSTALL SCRIPT HERE or CALL A FUNCTION

        with open("/tmp/idpss", "w") as f:
            f.writelines([
                "#!/usr/bin/python\n",
                "from dbg_utils.idp_server import idpss\n",
                "idpss.start()\n"
            ])
            f.close()
        
        os.system('chmod +x /tmp/idpss')
        os.system('sudo cp /tmp/idpss  /usr/bin/idpss')

        install.run(self)

setup(
    name = "dbg_utils",
    version = "0.1.2",
    keywords = ["pip", "pwn", "dbg"],
    description = "dbg utils for gdb",
    long_description_content_type='text/markdown',
    license = "MIT Licence",

    cmdclass={
        'install': IDPSSInstall,
    },

    author = "Lavender-Tree",
    author_email = "lavender.tree9988@gmail.com",
    url='https://github.com/Lavender-Tree/dbg_utils',

    packages = find_packages(),
    include_package_data = True,
    platforms = "any",
    install_requires = []
)