import subprocess

from parse_logs import parse_logs
from insert_mongo import insert_into_mongo

def main():
    parse_logs()
    insert_into_mongo()


if __name__ == "__main__":
    main()