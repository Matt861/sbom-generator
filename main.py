import argparse
from SBOM_Generators import GenMavenBom, GenNpmBom, GenPypiBom

def main():
    parser = argparse.ArgumentParser(description="Run project scripts individually or collectively.")
    parser.add_argument('--script', choices=['maven', 'npm', 'pypi', 'all'], help='Specify which script to run')
    args = parser.parse_args()

    if args.script == 'maven':
        GenMavenBom.run()
    elif args.script == 'npm':
        GenNpmBom.run()
    elif args.script == 'pypi':
        GenPypiBom.run()
    #elif args.script == 'all':
        #script1.run()
        #script2.run()


if __name__ == '__main__':
    main()
