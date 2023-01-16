from distutils.core import setup

setup(  name='MarPyModOidc',
        description='SSO Httpd module for direct OIDC',
        version="1.0",
        author='jmartdri',
        author_email='jmartdri@gmail.com',
        url='https://github.com/jmartdri/ModPyOidc',
        license='Apache 2.0',
        py_modules=['maroidc'],
        packages=['MarPyModOidc'],
        classifiers=[
            'Development Status :: 4 - Beta',
            'Programming Language :: Python',
            'Intended Audience :: System Administrators',
            'Environment :: Plugins',
            'Framework :: mod-python',
        ],
)

