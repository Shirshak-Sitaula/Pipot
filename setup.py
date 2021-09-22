from setuptools import setup


#def readme_file_contents():
 #   with open("Readme.rst") as readme_file:
  #      data = readme_file.read()
   # return data


setup(
    name='Pipot',
    version='1.0',
    description='Simple honeypot for Pi',
   # long_description=readme_file_contents(),
    author='Shirshu',
    packages=['Pipot'],
    zip_safe=False,
    Install_requires="requirement.txt"
)
