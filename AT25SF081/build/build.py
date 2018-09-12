import os, subprocess, shutil, sys
from multiprocessing import cpu_count
# from argparse import ArgumentParser
# parser = ArgumentParser()

here = os.path.abspath(os.path.dirname(__file__))
output_dir = os.path.join(here, '_build')
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

platform = sys.platform.lower()
if platform.startswith('linux'):
    platform = 'Linux'
elif platform.startswith('darwin'):
    platform = 'Darwin'
elif platform.startswith('win'):
    platform = 'Windows'
else:
    raise EnvironmentError("Unknown platform {}".format(platform))

generator = 'Unix Makefiles' if (platform == 'Linux' or platform == 'Darwin') else 'Visual Studio 15 2017 Win64'

subprocess.check_call(['cmake', '-G', generator, '-DCMAKE_BUILD_TYPE=Debug', here], cwd=output_dir)

so_file_path = os.path.join(output_dir, 'AT25SF081.so')
if generator == 'Unix Makefiles':
    subprocess.check_call(['make', '-j', str(cpu_count())], cwd=output_dir)
    if platform == 'Darwin':
        shutil.copy(os.path.join(output_dir, 'libAT25SF081.dylib'), so_file_path)
    else:
        shutil.copy(os.path.join(output_dir, 'libAT25SF081.so'), so_file_path)
else:
    subprocess.check_call(
        ['msbuild.exe', 'AT25SF081.sln', '/m:{}'.format(cpu_count()), '/t:AT25SF081', '/p:Platform=x64'], cwd=output_dir
    )
    shutil.copy(os.path.join(output_dir, 'Debug', 'AT25SF081.dll'), so_file_path)
