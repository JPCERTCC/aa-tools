from distutils.core import setup, Extension

setup(
    name="pyimpfuzzy",
    version="0.01",
    author="JPCERT/CC Analysis Center",
    author_email="aa-info@jpcert.or.jp",
    license="the GNU General Public License version 2",
    description="Python modules for impfuzzy",
    long_description="pyimpfuzzy is python module which calculate and compare the impfuzzy(import fuzzy hashing)",
    ext_modules=[Extension(
        "impfuzzyutil",
        sources=["impfuzzy_util.c"],
        libraries=["fuzzy"],
        library_dirs=["/usr/local/lib/", ],
        include_dirs=["/usr/local/include/", ],
    )],
    py_modules=["pyimpfuzzy"],
    url="https://github.com/JPCERTCC/aa-tools/",
)
